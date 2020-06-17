package crypter

import (
	"bytes"
	"google.golang.org/grpc/security/s2a/internal/crypter/testutil"
	s2a_proto "google.golang.org/grpc/security/s2a/internal/proto"
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
				netConn:               &fakeConn{},
				ciphersuite:           s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
				tlsVersion:            s2a_proto.TLSVersion_TLS1_3,
				inTrafficSecret:       testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				outTrafficSecret:      testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				handshakerServiceAddr: "test handshaker address",
			},
			outErr: true,
		},
		{
			desc: "invalid output traffic secret size",
			options: &ConnOptions{
				netConn:               &fakeConn{},
				ciphersuite:           s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
				tlsVersion:            s2a_proto.TLSVersion_TLS1_3,
				inTrafficSecret:       testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				outTrafficSecret:      testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				handshakerServiceAddr: "test handshaker address",
			},
			outErr: true,
		},
		{
			desc: "invalid tls version",
			options: &ConnOptions{
				netConn:               &fakeConn{},
				ciphersuite:           s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
				tlsVersion:            s2a_proto.TLSVersion_TLS1_2,
				inTrafficSecret:       testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				outTrafficSecret:      testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				handshakerServiceAddr: "test handshaker address",
			},
			outErr: true,
		},
		{
			desc: "basic with AES-128-GCM-SHA256",
			options: &ConnOptions{
				netConn:               &fakeConn{},
				ciphersuite:           s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
				tlsVersion:            s2a_proto.TLSVersion_TLS1_3,
				inTrafficSecret:       testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				outTrafficSecret:      testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				handshakerServiceAddr: "test handshaker address",
			},
			// outOverheadSize = header size + record type byte + tag size.
			outOverheadSize:          22,
			outHandshakerServiceAddr: "test handshaker address",
		},
		{
			desc: "basic with AES-256-GCM-SHA384",
			options: &ConnOptions{
				netConn:               &fakeConn{},
				ciphersuite:           s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
				tlsVersion:            s2a_proto.TLSVersion_TLS1_3,
				inTrafficSecret:       testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				outTrafficSecret:      testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				handshakerServiceAddr: "test handshaker address",
			},
			// outOverheadSize = header size + record type byte + tag size.
			outOverheadSize:          22,
			outHandshakerServiceAddr: "test handshaker address",
		},
		{
			desc: "basic with CHACHA20-POLY1305-SHA256",
			options: &ConnOptions{
				netConn:               &fakeConn{},
				ciphersuite:           s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
				tlsVersion:            s2a_proto.TLSVersion_TLS1_3,
				inTrafficSecret:       testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				outTrafficSecret:      testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				handshakerServiceAddr: "test handshaker address",
			},
			// outOverheadSize = header size + record type byte + tag size.
			outOverheadSize:          22,
			outHandshakerServiceAddr: "test handshaker address",
		},
		{
			desc: "basic with unusedBytes",
			options: &ConnOptions{
				netConn:               &fakeConn{},
				ciphersuite:           s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
				tlsVersion:            s2a_proto.TLSVersion_TLS1_3,
				inTrafficSecret:       testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				outTrafficSecret:      testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				unusedBytes:           testutil.Dehex("ffffffff"),
				handshakerServiceAddr: "test handshaker address",
			},
			outUnusedBytesBuf: testutil.Dehex("ffffffff"),
			// outOverheadSize = header size + record type byte + tag size.
			outOverheadSize:          22,
			outHandshakerServiceAddr: "test handshaker address",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			netConn, err := NewConn(tc.options)
			if got, want := err == nil, !tc.outErr; got != want {
				t.Errorf("NewConn(%v) = (err=nil) = %v, want %v", *tc.options, got, want)
			}
			if err == nil {
				conn := netConn.(*conn)
				if got, want := conn.unusedBytes, tc.outUnusedBytesBuf; !bytes.Equal(got, want) {
					t.Errorf("conn.unusedBytes = %v, want %v", got, want)
				}
				if got, want := conn.overheadSize, tc.outOverheadSize; got != want {
					t.Errorf("conn.overheadSize = %v, want %v", got, want)
				}
				if got, want := conn.handshakerServiceAddr, tc.outHandshakerServiceAddr; got != want {
					t.Errorf("conn.handshakerServiceAddr = %v, want %v", got, want)
				}
			}
		})
	}
}
