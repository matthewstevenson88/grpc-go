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
		outPayloadSizeLimit      int
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
				c:                     &fakeConn{},
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
				c:                     &fakeConn{},
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
				c:                     &fakeConn{},
				ciphersuite:           s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
				tlsVersion:            s2a_proto.TLSVersion_TLS1_2,
				inTrafficSecret:       testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				outTrafficSecret:      testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				handshakerServiceAddr: "test handshaker address",
			},
			outErr: true,
		},
		{
			desc: "basic 1",
			options: &ConnOptions{
				c:                     &fakeConn{},
				ciphersuite:           s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
				tlsVersion:            s2a_proto.TLSVersion_TLS1_3,
				inTrafficSecret:       testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				outTrafficSecret:      testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				handshakerServiceAddr: "test handshaker address",
			},
			outPayloadSizeLimit:      2282,
			outOverheadSize:          22,
			outHandshakerServiceAddr: "test handshaker address",
		},
		{
			desc: "basic 2",
			options: &ConnOptions{
				c:                     &fakeConn{},
				ciphersuite:           s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
				tlsVersion:            s2a_proto.TLSVersion_TLS1_3,
				inTrafficSecret:       testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				outTrafficSecret:      testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				handshakerServiceAddr: "test handshaker address",
			},
			outPayloadSizeLimit:      2282,
			outOverheadSize:          22,
			outHandshakerServiceAddr: "test handshaker address",
		},
		{
			desc: "basic 3",
			options: &ConnOptions{
				c:                     &fakeConn{},
				ciphersuite:           s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
				tlsVersion:            s2a_proto.TLSVersion_TLS1_3,
				inTrafficSecret:       testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				outTrafficSecret:      testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				unusedBytes:           testutil.Dehex("ffffffff"),
				handshakerServiceAddr: "test handshaker address",
			},
			outPayloadSizeLimit:      2282,
			outUnusedBytesBuf:        testutil.Dehex("ffffffff"),
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
				conn := netConn.(*Conn)
				if got, want := conn.payloadSizeLimit, tc.outPayloadSizeLimit; got != want {
					t.Errorf("conn.payloadSizeLimit = %v, want %v", got, want)
				}
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
