package crypter

import (
	"bytes"
	"google.golang.org/grpc/security/s2a/internal/crypter/testutil"
	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
	"net"
	"testing"
)

// fakeConn is a fake implementation of the net.Conn interface used for testing.
type fakeConn struct {
	net.Conn
	in  bytes.Buffer
	out bytes.Buffer
}

func (c *fakeConn) Read(b []byte) (n int, err error)  { return c.in.Read(b) }
func (c *fakeConn) Write(b []byte) (n int, err error) { return c.out.Write(b) }
func (c *fakeConn) Close() error                      { return nil }

func TestNewS2ARecordConn(t *testing.T) {
	for _, tc := range []struct {
		desc                     string
		options                  *ConnOptions
		outUnusedBytesBuf        []byte
		outOverheadSize          int
		outHandshakerServiceAddr string
		outErr                   bool
	}{
		{
			desc:   "nil conn options",
			outErr: true,
		},
		{
			desc: "invalid input traffic secret size",
			options: &ConnOptions{
				NetConn:          &fakeConn{},
				Ciphersuite:      s2apb.Ciphersuite_AES_256_GCM_SHA384,
				TlsVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				OutTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				HsAddr:           "test handshaker address",
			},
			outErr: true,
		},
		{
			desc: "invalid output traffic secret size",
			options: &ConnOptions{
				NetConn:          &fakeConn{},
				Ciphersuite:      s2apb.Ciphersuite_AES_256_GCM_SHA384,
				TlsVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				OutTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				HsAddr:           "test handshaker address",
			},
			outErr: true,
		},
		{
			desc: "invalid tls version",
			options: &ConnOptions{
				NetConn:          &fakeConn{},
				Ciphersuite:      s2apb.Ciphersuite_AES_128_GCM_SHA256,
				TlsVersion:       s2apb.TLSVersion_TLS1_2,
				InTrafficSecret:  testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				OutTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				HsAddr:           "test handshaker address",
			},
			outErr: true,
		},
		{
			desc: "basic with AES-128-GCM-SHA256",
			options: &ConnOptions{
				NetConn:          &fakeConn{},
				Ciphersuite:      s2apb.Ciphersuite_AES_128_GCM_SHA256,
				TlsVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				OutTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				HsAddr:           "test handshaker address",
			},
			// outOverheadSize = header size (5) + record type byte (1) +
			// tag size (16).
			outOverheadSize:          22,
			outHandshakerServiceAddr: "test handshaker address",
		},
		{
			desc: "basic with AES-256-GCM-SHA384",
			options: &ConnOptions{
				NetConn:          &fakeConn{},
				Ciphersuite:      s2apb.Ciphersuite_AES_256_GCM_SHA384,
				TlsVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				OutTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				HsAddr:           "test handshaker address",
			},
			// outOverheadSize = header size (5) + record type byte (1) +
			// tag size (16).
			outOverheadSize:          22,
			outHandshakerServiceAddr: "test handshaker address",
		},
		{
			desc: "basic with CHACHA20-POLY1305-SHA256",
			options: &ConnOptions{
				NetConn:          &fakeConn{},
				Ciphersuite:      s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
				TlsVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				OutTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				HsAddr:           "test handshaker address",
			},
			// outOverheadSize = header size (5) + record type byte (1) +
			// tag size (16).
			outOverheadSize:          22,
			outHandshakerServiceAddr: "test handshaker address",
		},
		{
			desc: "basic with unusedBytes",
			options: &ConnOptions{
				NetConn:          &fakeConn{},
				Ciphersuite:      s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
				TlsVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				OutTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				UnusedBuf:        testutil.Dehex("ffffffff"),
				HsAddr:           "test handshaker address",
			},
			outUnusedBytesBuf: testutil.Dehex("ffffffff"),
			// outOverheadSize = header size (5) + record type byte (1) +
			// tag size (16).
			outOverheadSize:          22,
			outHandshakerServiceAddr: "test handshaker address",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			NetConn, err := NewConn(tc.options)
			if got, want := err == nil, !tc.outErr; got != want {
				t.Errorf("NewConn(%v) = (err=nil) = %v, want %v", *tc.options, got, want)
			}
			if err != nil {
				return
			}
			conn := NetConn.(*conn)
			if got, want := conn.unusedBuf, tc.outUnusedBytesBuf; !bytes.Equal(got, want) {
				t.Errorf("conn.unusedBytes = %v, want %v", got, want)
			}
			if got, want := conn.overheadSize, tc.outOverheadSize; got != want {
				t.Errorf("conn.overheadSize = %v, want %v", got, want)
			}
			if got, want := conn.hsAddr, tc.outHandshakerServiceAddr; got != want {
				t.Errorf("conn.HsAddr = %v, want %v", got, want)
			}
		})
	}
}

func TestConnRead(t *testing.T) {
	conn := &conn{}
	if _, err := conn.Read(nil); err == nil {
		t.Errorf("read is unimplemented")
	}
}

func TestConnWrite(t *testing.T) {
	conn := &conn{}
	if _, err := conn.Write(nil); err == nil {
		t.Errorf("write is unimplemented")
	}
}
