package record

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
	"google.golang.org/grpc/security/s2a/internal/record/internal/halfconn"
)

// contentType is the `ContentType` as described in
// https://tools.ietf.org/html/rfc8446#section-5.1
type contentType byte

const (
	alert           contentType = 21
	handshake       contentType = 22
	applicationData contentType = 23
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
	tlsApplicationData = 23
	// tlsLegacyRecordVersion is the legacy record version of the TLS 1.3
	// record header. 771 == 0x03 + 0x03 in hex.
	tlsLegacyRecordVersion = 771
	// tlsRecordTypeSize is the size in bytes of the TLS 1.3 record type.
	tlsRecordTypeSize = 1
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
	tlsHandshakeKeyUpdateMsgSize = tlsHandshakeMsgTypeSize + tlsHandshakeLengthSize + 1
)

const (
	// TODO(gud): Revisit what initial size to use when implementating Write.
	// outBufSize is the initial write buffer size in bytes.
	outBufSize = 32 * 1024
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
	// outRecordsBuf is a buffer used to contain outgoing TLS records before
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

// ConnOptions holds the options used for creating a new conn object.
type ConnOptions struct {
	// NetConn is the current TLS record.
	NetConn net.Conn
	// Ciphersuite is the TLS ciphersuite negotiated by the S2A's handshaker
	// module.
	Ciphersuite s2apb.Ciphersuite
	// TLSVersion is the TLS version number that the S2A's handshaker module
	// used to set up the session.
	TLSVersion s2apb.TLSVersion
	// InTrafficSecret is the key for the in bound direction.
	InTrafficSecret []byte
	// OutTrafficSecret is the key for the out bound direction.
	OutTrafficSecret []byte
	// UnusedBuf is the data read from the network that has not yet been
	// decrypted.
	UnusedBuf []byte
	// InSequence is the sequence number of the next, incoming, TLS record.
	InSequence uint64
	// OutSequence is the sequence number of the next, outgoing, TLS record.
	OutSequence uint64
	// hsAddr stores the address of the S2A handshaker service.
	HsAddr string
}

func NewConn(o *ConnOptions) (net.Conn, error) {
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
	// TODO(gud): Potentially optimize unusedBuf with pre-allocation.
	if o.UnusedBuf != nil {
		unusedBuf = make([]byte, len(o.UnusedBuf))
		copy(unusedBuf, o.UnusedBuf)
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

// Read reads and decrypts a frame from the underlying connection, and copies the
// decrypted payload into b. If the size of the payload is greater than len(b),
// Read retains the remaining bytes in an internal buffer, and subsequent calls
// to Read will read from this buffer until it is exhausted.
func (p *conn) Read(b []byte) (n int, err error) {
	if len(p.pendingApplicationData) == 0 {
		// Read a completed record from the wire.
		completedRecord, err := p.readCompletedRecord()
		if err != nil {
			return 0, err
		}
		// Now we have a complete record, so split the header and validate it.
		header, ciphertext, err := splitAndValidateHeader(completedRecord)
		if err != nil {
			return 0, err
		}
		// Decrypt the ciphertext.
		p.pendingApplicationData, err = p.inConn.Decrypt(ciphertext[:0], ciphertext, header)
		if err != nil {
			return 0, err
		}
		// Remove the 0 padding and the record type byte.
		msgType := p.stripPaddingAndType()
		switch msgType {
		case alert:
			if len(p.pendingApplicationData) != tlsAlertSize {
				return 0, errors.New("invalid alert message size")
			}
			if p.pendingApplicationData[1] == byte(closeNotify) {
				if err = p.Conn.Close(); err != nil {
					return 0, err
				}
			}
			// TODO: add support for more alert types?
			return 0, nil
		case handshake:
			handshakeMsgType := p.pendingApplicationData[0]
			if handshakeMsgType == tlsHandshakeKeyUpdatePrefix {
				msgLen := bigEndianInt24(p.pendingApplicationData[tlsHandshakeMsgTypeSize : tlsHandshakeMsgTypeSize+tlsHandshakeLengthSize])
				if msgLen != tlsHandshakeKeyUpdateMsgSize || len(p.pendingApplicationData) != tlsHandshakeKeyUpdateMsgSize {
					return 0, errors.New("invalid handshake key update message length")
				}
				if !(p.pendingApplicationData[tlsHandshakeMsgTypeSize+tlsHandshakeLengthSize] == byte(updateNotRequested) ||
					p.pendingApplicationData[tlsHandshakeMsgTypeSize+tlsHandshakeLengthSize] == byte(updateRequested)) {
					return 0, errors.New("invalid handshake key update message")
				}
				if err = p.inConn.UpdateKey(); err != nil {
					return 0, err
				}
				return 0, nil
			} else if handshakeMsgType == tlsHandshakeNewSessionTicket {
				// TODO: implement this later.
				return 0, errors.New("new session ticket unimplemented")
			}

			// TODO: add support for more handshake message types?
			// Close the connection on unrecognized handshake message type.
			if err = p.Conn.Close(); err != nil {
				return 0, err
			}
			return 0, errors.New("unknown handshake message type")
		case applicationData:
			// Do nothing if the type is application data.
		default:
			// Close the connection on unrecognized message type.
			if err = p.Conn.Close(); err != nil {
				return 0, err
			}
			return 0, errors.New("unknown record type")
		}
	}

	n = copy(b, p.pendingApplicationData)
	p.pendingApplicationData = p.pendingApplicationData[n:]
	return n, nil
}

func (p *conn) Write(b []byte) (n int, err error) {
	// TODO: Implement this.
	return 0, errors.New("write unimplemented")
}

// stripPaddingAndType strips the 0 padding and record type from a record and
// returns the record type.
func (p *conn) stripPaddingAndType() contentType {
	i := len(p.pendingApplicationData) - 1
	for i > 0 {
		if p.pendingApplicationData[i] != 0 {
			break
		}
		i--
	}
	ct := contentType(p.pendingApplicationData[i])
	p.pendingApplicationData = p.pendingApplicationData[:i]
	return ct
}

// readCompletedRecord reads from the wire until a record is completed and
// returns the completed record.
func (p *conn) readCompletedRecord() (completedRecord []byte, err error) {
	completedRecord, p.nextRecord, err = parseRecord(p.nextRecord, tlsRecordMaxPlaintextSize)
	if err != nil {
		return nil, err
	}
	// Check whether the next record to be decrypted has been completely
	// received yet.
	if len(completedRecord) == 0 {
		copy(p.unusedBuf, p.nextRecord)
		p.unusedBuf = p.unusedBuf[:len(p.nextRecord)]
		// Always copy next incomplete record to the beginning of the
		// unusedBuf buffer and reset nextRecord to it.
		p.nextRecord = p.unusedBuf
	}
	// Keep reading from the wire until we have a complete record.
	for len(completedRecord) == 0 {
		if len(p.unusedBuf) == cap(p.unusedBuf) {
			tmp := make([]byte, len(p.unusedBuf), cap(p.unusedBuf)+tlsRecordMaxPlaintextSize)
			copy(tmp, p.unusedBuf)
			p.unusedBuf = tmp
		}
		n, err := p.Conn.Read(p.unusedBuf[len(p.unusedBuf):min(cap(p.unusedBuf), len(p.unusedBuf)+tlsRecordMaxPlaintextSize)])
		if err != nil {
			return nil, err
		}
		p.unusedBuf = p.unusedBuf[:len(p.unusedBuf)+n]
		completedRecord, p.nextRecord, err = parseRecord(p.unusedBuf, tlsRecordMaxPlaintextSize)
		if err != nil {
			return nil, err
		}
	}
	return completedRecord, nil
}

// readRecord parses the provided buffer and returns a completed record and any
// remaining bytes in that buffer. If the record is incomplete, nil is returned
// for the first return value and the given byte buffer is returned for the
// second return value.
func parseRecord(b []byte, maxLen uint16) ([]byte, []byte, error) {
	// If the size field is not complete, return the provided buffer as
	// remaining buffer.
	if len(b) < tlsRecordHeaderSize {
		return nil, b, nil
	}
	msgLenField := b[tlsRecordHeaderTypeSize+tlsRecordHeaderLegacyRecordVersionSize : tlsRecordHeaderSize]
	length := binary.BigEndian.Uint16(msgLenField)
	if length > maxLen {
		return nil, nil, fmt.Errorf("record length larger than the limit %d", maxLen)
	}
	if len(b) < int(length)+tlsRecordHeaderSize {
		// Record is not complete yet.
		return nil, b, nil
	}
	return b[:tlsRecordHeaderSize+length], b[tlsRecordHeaderSize+length:], nil
}

// splitAndValidateHeader splits the header from the ciphertext in the completed
// record and returns them. Note that the header is checked for validity, and an
// error is returned when an invalid header is parsed.
func splitAndValidateHeader(completedRecord []byte) (header, ciphertext []byte, err error) {
	header = completedRecord[:tlsRecordHeaderSize]
	ciphertext = completedRecord[tlsRecordHeaderSize:]
	headerType := header[0]
	if headerType != tlsApplicationData {
		return nil, nil, fmt.Errorf("incorrect type in the header")
	}
	legacyRecordVersion := binary.BigEndian.Uint16(header[tlsRecordHeaderTypeSize : tlsRecordHeaderTypeSize+tlsRecordHeaderLegacyRecordVersionSize])
	if legacyRecordVersion != tlsLegacyRecordVersion {
		return nil, nil, fmt.Errorf("incorrect legacy record version in the header")
	}
	return header, ciphertext, nil
}

// bidEndianInt24 converts the given byte buffer of at least size 3 and
// outputs the resulting 24 bit integer as a uint32. This is needed because
// TLS 1.3 requires 3 byte integers, and the binary.BigEndian package does
// not provide a way to transform a byte buffer into a 3 byte integer.
func bigEndianInt24(b []byte) uint32 {
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
