package crypter

import (
	"errors"
	"fmt"
	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
	"net"
)

const (
	// The TLS 1.3-specific constants below (tlsRecordMaxPlaintextSize,
	// tlsRecordHeaderSize, tlsRecordTypeSize) were taken from
	// https://tools.ietf.org/html/rfc8446#section-5.1

	// tlsRecordMaxPlaintextSize is the maximum size in bytes of the plaintext
	// in a single TLS 1.3 record.
	tlsRecordMaxPlaintextSize = 16384 // 2^14
	// tlsRecordHeaderSize is the size in bytes of the TLS 1.3 record header.
	tlsRecordHeaderSize = 5
	// tlsRecordTypeSize is the size in bytes of the TLS 1.3 record type.
	tlsRecordTypeSize = 1
	// TODO(gud): Revisit what initial size to use when implementating Write.
	// outBufSize is the initial write buffer size in bytes.
	outBufSize = 32 * 1024
)

// conn represents a secured TLS connection. It implements the net.Conn
// interface.
type conn struct {
	net.Conn
	// inConn is the half connection responsible for decrypting incoming bytes.
	inConn *S2AHalfConnection
	// outConn is the half connection responsible for encrypting outgoing bytes.
	outConn *S2AHalfConnection
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
	netConn                                      net.Conn
	ciphersuite                                  s2apb.Ciphersuite
	tlsVersion                                   s2apb.TLSVersion
	inTrafficSecret, outTrafficSecret, unusedBuf []byte
	// TODO(rnkim): Add initial sequence number to half conneciton.
	inSequence, outSequence uint64
	hsAddr                  string
}

func NewConn(o *ConnOptions) (net.Conn, error) {
	if o == nil {
		return nil, errors.New("conn options must not be nil")
	}
	if o.tlsVersion != s2apb.TLSVersion_TLS1_3 {
		return nil, errors.New("TLS version must be TLS 1.3")
	}

	inConn, err := NewHalfConn(o.ciphersuite, o.inTrafficSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create inbound half connection: %v", err)
	}
	outConn, err := NewHalfConn(o.ciphersuite, o.outTrafficSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create outbound half connection: %v", err)
	}

	// TODO(rnkim): Add TagSize() to Half Connection.
	// The tag size for the in/out connections should be the same.
	overheadSize := tlsRecordHeaderSize + tlsRecordTypeSize + inConn.aeadCrypter.tagSize()
	var unusedBuf []byte
	// TODO(gud): Potentially optimize unusedBuf with pre-allocation.
	if o.unusedBuf != nil {
		unusedBuf = make([]byte, len(o.unusedBuf))
		copy(unusedBuf, o.unusedBuf)
	}

	s2aConn := &conn{
		Conn:          o.netConn,
		inConn:        inConn,
		outConn:       outConn,
		unusedBuf:     unusedBuf,
		outRecordsBuf: make([]byte, outBufSize),
		nextRecord:    unusedBuf,
		overheadSize:  overheadSize,
		hsAddr:        o.hsAddr,
	}
	return s2aConn, nil
}

func (p *conn) Read(b []byte) (n int, err error) {
	// TODO: Implement this.
	return 0, errors.New("read unimplemented")
}

func (p *conn) Write(b []byte) (n int, err error) {
	// TODO: Implement this.
	return 0, errors.New("write unimplemented")
}
