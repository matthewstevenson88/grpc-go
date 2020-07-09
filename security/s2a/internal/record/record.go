package record

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"

	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
	"google.golang.org/grpc/security/s2a/internal/record/internal/halfconn"
)

// recordType is the `ContentType` as described in
// https://tools.ietf.org/html/rfc8446#section-5.1
type recordType byte

const (
	alert           recordType = 21
	handshake       recordType = 22
	applicationData recordType = 23
)

// keyUpdateRequest is the `KeyUpdateRequest` as described in
// https://tools.ietf.org/html/rfc8446#section-4.6.3
type keyUpdateRequest byte

const (
	updateNotRequested keyUpdateRequest = 0
	updateRequested    keyUpdateRequest = 1
)

// alertDescription is the `AlertDescription` as described in
// https://tools.ietf.org/html/rfc8446#section-6
type alertDescription byte

const (
	closeNotify alertDescription = 0
)

const (
	// The TLS 1.3-specific constants below (tlsRecordMaxPlaintextSize,
	// tlsRecordHeaderSize, tlsRecordTypeSize) were taken from
	// https://tools.ietf.org/html/rfc8446#section-5.1

	// tlsRecordMaxPlaintextSize is the maximum size in bytes of the plaintext
	// in a single TLS 1.3 record.
	tlsRecordMaxPlaintextSize = 16384 // 2^14
	// tlsRecordHeaderTypeSize is the size in bytes of the TLS 1.3 record
	// header type.
	tlsRecordHeaderTypeSize = 1
	// tlsRecordHeaderLegacyRecordVersionSize is the size in bytes of the TLS
	// 1.3 record header legacy record version.
	tlsRecordHeaderLegacyRecordVersionSize = 2
	// tlsRecordHeaderPayloadLengthSize is the size in bytes of the TLS 1.3
	// record header payload length.
	tlsRecordHeaderPayloadLengthSize = 2
	// tlsRecordHeaderSize is the size in bytes of the TLS 1.3 record header.
	tlsRecordHeaderSize = tlsRecordHeaderTypeSize + tlsRecordHeaderLegacyRecordVersionSize + tlsRecordHeaderPayloadLengthSize
	// tlsApplicationData is the application data type of the TLS 1.3 record
	// header.
	tlsApplicationData = 0x17
	// tlsLegacyRecordVersion is the legacy record version of the TLS record.
	tlsLegacyRecordVersion = 0x03
	// tlsRecordTypeSize is the size in bytes of the TLS 1.3 record type.
	tlsRecordTypeSize = 1
	// TODO(gud): Revisit what initial size to use when implementating Write.
	// outBufSize is the initial write buffer size in bytes.
	outBufSize = 32 * 1024
	// tlsAlertSize is the size in bytes of an alert of TLS 1.3.
	tlsAlertSize = 2
)

const (
	// tlsHandshakeNewSessionTicket is the prefix of a handshake new session
	// ticket message of TLS 1.3.
	tlsHandshakeNewSessionTicket = 0x04
	// tlsHandshakeKeyUpdatePrefix is the prefix of a handshake key update
	// message of TLS 1.3.
	tlsHandshakeKeyUpdatePrefix = 0x18
	// tlsHandshakeMsgTypeSize is the size in bytes of the TLS 1.3 handshake
	// message type field.
	tlsHandshakeMsgTypeSize = 1
	// tlsHandshakeLengthSize is the size in bytes of the TLS 1.3 handshake
	// message length field.
	tlsHandshakeLengthSize = 3
	// tlsHandshakeLengthSize is the size in bytes of the TLS 1.3 handshake
	// key update message.
	tlsHandshakeKeyUpdateMsgSize = 1
)

// conn represents a secured TLS connection. It implements the net.Conn
// interface.
type conn struct {
	net.Conn
	// inConn is the half connection responsible for decrypting incoming bytes.
	inConn *halfconn.S2AHalfConnection
	// outConn is the half connection responsible for encrypting outgoing bytes.
	outConn *halfconn.S2AHalfConnection
	// pendingApplicationData holds data that has been read from the connection
	// and decrypted, but has not yet been returned by Read.
	pendingApplicationData []byte
	// unusedBuf holds data read from the network that has not yet been
	// decrypted. This data might not consist of a complete record. It may
	// consist of several records, the last of which could be incomplete.
	unusedBuf []byte
	// outRecordsBuf is a buffer used to store outgoing TLS records before
	// they are written to the network.
	outRecordsBuf []byte
	// nextRecord stores the next record info in the unusedBuf buffer.
	nextRecord []byte
	// overheadSize is the overhead size in bytes of each TLS 1.3 record, which
	// is computed as overheadSize = header size + record type byte + tag size.
	// Note that there is no padding by zeros in the overhead calculation.
	overheadSize int
	// hsAddr stores the address of the S2A handshaker service.
	hsAddr string
}

// ConnParameters holds the parameters used for creating a new conn object.
type ConnParameters struct {
	// NetConn is the TCP connection to the peer. This parameter is required.
	NetConn net.Conn
	// Ciphersuite is the TLS ciphersuite negotiated by the S2A handshaker
	// service. This parameter is required.
	Ciphersuite s2apb.Ciphersuite
	// TLSVersion is the TLS version number negotiated by the S2A handshaker
	// service. This parameter is required.
	TLSVersion s2apb.TLSVersion
	// InTrafficSecret is the traffic secret used to derive the session key for
	// the inbound direction. This parameter is required.
	InTrafficSecret []byte
	// OutTrafficSecret is the traffic secret used to derive the session key
	// for the outbound direction. This parameter is required.
	OutTrafficSecret []byte
	// UnusedBuf is the data read from the network that has not yet been
	// decrypted. This parameter is optional. If not provided, then no
	// application data was sent in the same flight of messages as the final
	// handshake message.
	UnusedBuf []byte
	// InSequence is the sequence number of the next, incoming, TLS record.
	// This parameter is required.
	InSequence uint64
	// OutSequence is the sequence number of the next, outgoing, TLS record.
	// This parameter is required.
	OutSequence uint64
	// hsAddr stores the address of the S2A handshaker service. This parameter
	// is optional. If not provided, then TLS resumption is disabled.
	HsAddr string
}

func NewConn(o *ConnParameters) (net.Conn, error) {
	if o == nil {
		return nil, errors.New("conn options must not be nil")
	}
	if o.TLSVersion != s2apb.TLSVersion_TLS1_3 {
		return nil, errors.New("TLS version must be TLS 1.3")
	}

	inConn, err := halfconn.New(o.Ciphersuite, o.InTrafficSecret, o.InSequence)
	if err != nil {
		return nil, fmt.Errorf("failed to create inbound half connection: %v", err)
	}
	outConn, err := halfconn.New(o.Ciphersuite, o.OutTrafficSecret, o.OutSequence)
	if err != nil {
		return nil, fmt.Errorf("failed to create outbound half connection: %v", err)
	}

	// The tag size for the in/out connections should be the same.
	overheadSize := tlsRecordHeaderSize + tlsRecordTypeSize + inConn.TagSize()
	var unusedBuf []byte
	if o.UnusedBuf != nil {
		unusedBuf = make([]byte, len(o.UnusedBuf))
		copy(unusedBuf, o.UnusedBuf)
	} else {
		unusedBuf = make([]byte, 0, 2*tlsRecordMaxPlaintextSize-1)
	}

	s2aConn := &conn{
		Conn:          o.NetConn,
		inConn:        inConn,
		outConn:       outConn,
		unusedBuf:     unusedBuf,
		outRecordsBuf: make([]byte, outBufSize),
		nextRecord:    unusedBuf,
		overheadSize:  overheadSize,
		hsAddr:        o.HsAddr,
	}
	return s2aConn, nil
}

func (p *conn) Read(b []byte) (n int, err error) {
	// TODO: Implement this.
	return 0, errors.New("read unimplemented")
}

// Write encrypts, frames, and writes bytes from b to the underlying connection.
func (p *conn) Write(b []byte) (n int, err error) {
	return p.writeTlsRecord(b, tlsApplicationData)
}

func (p *conn) writeTlsRecord(b []byte, recordType byte) (n int, err error) {
	n = len(b)
	// Calculate the output buffer size.
	numOfRecords := int(math.Ceil(float64(len(b)) / float64(tlsRecordMaxPlaintextSize)))
	totalNumOfRecordBytes := len(b) + numOfRecords*17
	partialBSize := len(b)
	if totalNumOfRecordBytes > outBufSize {
		totalNumOfRecordBytes = outBufSize
		partialBSize = outBufSize / tlsRecordMaxPlaintextSize * tlsRecordHeaderPayloadLengthSize
	}
	if len(p.outRecordsBuf) < totalNumOfRecordBytes {
		p.outRecordsBuf = make([]byte, totalNumOfRecordBytes)
	}
	for bStart := 0; bStart < len(b); bStart += partialBSize {
		bEnd := bStart + partialBSize
		if bEnd > len(b) {
			bEnd = len(b)
		}
		partialB := b[bStart:bEnd]
		outRecordsBufIndex := 0
		for len(partialB) > 0 {
			// Construct the payload consisting of app data and record type.
			dataLen := len(partialB)
			if dataLen > len(p.outRecordsBuf) {
				dataLen = len(p.outRecordsBuf)
			}
			buff := partialB[:dataLen]
			partialB = partialB[dataLen:]
			payload := append(buff, recordType)
			// Construct the header.
			newHeader, err := buildHeader(payload, recordType)
			if err != nil {
				return bStart, err
			}
			// Encrypt the payload using header as aad.
			encrypted, err := p.encryptPayload(payload, newHeader)
			if err != nil {
				return bStart, err
			}
			binary.BigEndian.PutUint16(p.outRecordsBuf[outRecordsBufIndex:], binary.BigEndian.Uint16(append(newHeader, encrypted...)))
			outRecordsBufIndex += dataLen + len(buff)
		}
		partialWritten, err := p.Conn.Write(p.outRecordsBuf[:outRecordsBufIndex])
		if err != nil {
			return bStart + partialWritten, err
		}
		p.outRecordsBuf = make([]byte, outBufSize)
	}
	return n, nil
}

// encryptPayload takes in b as the payload and feeds it into the ADEED crypter
// with header as the aad.
func (p *conn) encryptPayload(b, header []byte) ([]byte, error) {
	encrypted, err := p.outConn.Encrypt(p.outRecordsBuf, b, header)
	if err != nil {
		return nil, err
	}
	return encrypted, err
}

// buildHeader takes in b as the payload and builds the header for it.
func buildHeader(b []byte, recordType byte) (header []byte, err error) {
	if len(b) > tlsRecordMaxPlaintextSize {
		return nil, errors.New("plaintext length exceeds max size")
	}
	dataLen := make([]byte, tlsRecordHeaderPayloadLengthSize)
	binary.BigEndian.PutUint16(dataLen, uint16(len(b)+17))
	return append([]byte{recordType, tlsLegacyRecordVersion, tlsLegacyRecordVersion}, dataLen...), nil
}
