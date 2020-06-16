package crypter

import (
	"errors"
	"fmt"
	s2a_proto "google.golang.org/grpc/security/s2a/internal/proto"
	"net"
)

const (
	// TODO(rnkim): Add more documentation around where these values come from.
	// s2aRecordMaxCiphertextSize is the maximum size of an S2A record message.
	s2aRecordMaxSize = 2*1024 + 256
	// s2aRecordHeaderSize is the size of the record header in bytes.
	s2aRecordHeaderSize = 5
	// s2aRecordTypeSize is the size of the record type.
	s2aRecordTypeSize = 1
	// s2aWriteBufferInitialSize is the initial write buffer size.
	s2aWriteBufferInitialSize = 32 * 1024
)

// Conn represents a secured connection. It implements the net.Conn interface.
type Conn struct {
	net.Conn
	// inConnection is the half connection responsible for decrypting incoming
	// bytes.
	inConnection S2AHalfConnection
	// outConnection is the half connection responsible for encrypting outgoing
	// bytes
	outConnection S2AHalfConnection
	// buf holds data that has been read from the connection and decrypted, but
	// has not yet been returned by Read.
	buf []byte
	// payloadSizeLimit is the maximum size of the payload.
	payloadSizeLimit int
	// unusedBytes holds data read from the network that has not yet been
	// decrypted. This data might not compose a complete frame.
	unusedBytes []byte
	// writeBuf is a buffer used to contain encrypted frames before being
	// written to the network.
	writeBuf []byte
	// nextFrame stores the next frame info in the unusedBytes buffer.
	nextFrame []byte
	// overheadSize is the calculated overhead size of each frame.
	overheadSize int
	// handshakerServiceAddr stores the address of the handshaker service.
	handshakerServiceAddr string
}

// ConnOptions holds the options used for creating a new Conn object.
type ConnOptions struct {
	c                                              net.Conn
	ciphersuite                                    s2a_proto.Ciphersuite
	tlsVersion                                     s2a_proto.TLSVersion
	inTrafficSecret, outTrafficSecret, unusedBytes []byte
	handshakerServiceAddr                          string
	// TODO(rnkim): Pass these to HalfConn constructor.
	inSeq, outSeq int
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
		return nil, fmt.Errorf("failed to create input half connection: %v", err)
	}
	outConnection, err := NewHalfConn(o.ciphersuite, o.outTrafficSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create output half connection: %v", err)
	}

	// TODO(rnkim): Add TagSize() to Half Connection? The code below won't work
	// once we move HalfConn into it's own directory.
	overheadSize := s2aRecordHeaderSize + s2aRecordTypeSize + inConnection.aeadCrypter.tagSize()
	payloadSizeLimit := s2aRecordMaxSize - overheadSize
	var unusedBytesBuf []byte
	if o.unusedBytes == nil {
		// We pre-allocate unusedBytes to be of size
		// 2*s2aRecordMaxPlaintextSize-1 during initialization. We only
		// read from the network into unusedBytes when unusedBytes does not
		// contain a complete frame, which is at most
		// s2aRecordMaxPlaintextSize-1 (bytes). And we read at most
		// s2aRecordMaxPlaintextSize (bytes) data into unusedBytes at one
		// time. Therefore, 2*s2aRecordMaxPlaintextSize-1 is large enough
		// to buffer data read from the network.
		unusedBytesBuf = make([]byte, 0, 2*s2aRecordMaxSize-1)
	} else {
		unusedBytesBuf = make([]byte, len(o.unusedBytes))
		copy(unusedBytesBuf, o.unusedBytes)
	}

	s2aConn := &Conn{
		Conn:                  o.c,
		inConnection:          inConnection,
		outConnection:         outConnection,
		payloadSizeLimit:      payloadSizeLimit,
		unusedBytes:           unusedBytesBuf,
		writeBuf:              make([]byte, s2aWriteBufferInitialSize),
		nextFrame:             unusedBytesBuf,
		overheadSize:          overheadSize,
		handshakerServiceAddr: o.handshakerServiceAddr,
	}
	return s2aConn, nil
}

func (p *Conn) Read(b []byte) (n int, err error) {
	// TODO: Implement this.
	panic("Read unimplemented")
}

func (p *Conn) Write(b []byte) (n int, err error) {
	// TODO: Implement this.
	panic("Write unimplemented")
}
