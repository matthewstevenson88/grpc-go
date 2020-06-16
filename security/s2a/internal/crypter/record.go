package crypter

import (
	"errors"
	"fmt"
	s2a_proto "google.golang.org/grpc/security/s2a/internal/proto"
	"net"
)

const (
	// TODO(rnkim): Add more documentation around where these values come from.
	// s2aRecordMaxPlaintextSize is the maximum size of an S2A record message.
	s2aRecordMaxPlaintextSize = 16384 // 2^14
	// s2aRecordHeaderSize is the size of the record header in bytes.
	s2aRecordHeaderSize = 5
	// s2aRecordTypeSize is the size of the record type.
	s2aRecordTypeSize = 1
	// s2aOutgoingRecordsBufInitialSize is the initial write buffer size.
	s2aOutgoingRecordsBufInitialSize = 32 * 1024
)

// conn represents a secured TLS connection. It implements the net.Conn
// interface.
type conn struct {
	net.Conn
	// inConnection is the half connection responsible for decrypting incoming
	// bytes.
	inConnection S2AHalfConnection
	// outConnection is the half connection responsible for encrypting outgoing
	// bytes.
	outConnection S2AHalfConnection
	// pendingApplicationData holds data that has been read from the connection
	// and decrypted, but has not yet been returned by Read.
	pendingApplicationData []byte
	// unusedBytes holds data read from the network that has not yet been
	// decrypted. This data might not compose a complete record. It may consist
	// of several records, the last of which could be incomplete.
	unusedBytes []byte
	// outgoingRecordsBuf is a buffer used to contain outgoing TLS records
	// before they are written to the network.
	outgoingRecordsBuf []byte
	// nextRecord stores the next record info in the unusedBytes buffer.
	nextRecord []byte
	// overheadSize is the overhead size of each record.
	overheadSize int
	// handshakerServiceAddr stores the address of the S2A handshaker service.
	handshakerServiceAddr string
}

// ConnOptions holds the options used for creating a new conn object.
type ConnOptions struct {
	netConn                                        net.Conn
	ciphersuite                                    s2a_proto.Ciphersuite
	tlsVersion                                     s2a_proto.TLSVersion
	inTrafficSecret, outTrafficSecret, unusedBytes []byte
	// TODO(rnkim): Pass these to HalfConn constructor.
	inSequence, outSequence uint64
	handshakerServiceAddr   string
}

func NewConn(o *ConnOptions) (net.Conn, error) {
	if o == nil {
		return nil, errors.New("conn options must be not nil")
	}
	if o.tlsVersion != s2a_proto.TLSVersion_TLS1_3 {
		return nil, errors.New("TLS version must be TLS 1.3")
	}

	inConnection, err := NewHalfConn(o.ciphersuite, o.inTrafficSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create inbound half connection: %v", err)
	}
	outConnection, err := NewHalfConn(o.ciphersuite, o.outTrafficSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create outbound half connection: %v", err)
	}

	// TODO(rnkim): Add TagSize() to Half Connection? The code below won't work
	// once we move HalfConn into it's own directory.
	// Note: The tag size for the in/out connections should be the same.
	// The inConnection was arbitrarily chosen below.
	overheadSize := s2aRecordHeaderSize + s2aRecordTypeSize + inConnection.aeadCrypter.tagSize()
	var unusedBytesBuf []byte
	// TODO(gud): Potentially optimize unusedBytesBuf with pre-allocation.
	if o.unusedBytes != nil {
		unusedBytesBuf = make([]byte, len(o.unusedBytes))
		copy(unusedBytesBuf, o.unusedBytes)
	}

	s2aConn := &conn{
		Conn:                  o.netConn,
		inConnection:          inConnection,
		outConnection:         outConnection,
		unusedBytes:           unusedBytesBuf,
		outgoingRecordsBuf:    make([]byte, s2aOutgoingRecordsBufInitialSize),
		nextRecord:            unusedBytesBuf,
		overheadSize:          overheadSize,
		handshakerServiceAddr: o.handshakerServiceAddr,
	}
	return s2aConn, nil
}

func (p *conn) Read(b []byte) (n int, err error) {
	// TODO: Implement this.
	panic("Read unimplemented")
}

func (p *conn) Write(b []byte) (n int, err error) {
	// TODO: Implement this.
	panic("Write unimplemented")
}
