/*
 *
 * Copyright 2020 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package handshaker

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"google.golang.org/grpc"
	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

var (
	// testClientHandshakerOptions are the client handshaker options used for testing
	testClientHandshakerOptions = &ClientHandshakerOptions{
		MinTLSVersion: s2apb.TLSVersion_TLS1_2,
		MaxTLSVersion: s2apb.TLSVersion_TLS1_3,
		TLSCiphersuites: []s2apb.Ciphersuite{
			s2apb.Ciphersuite_AES_128_GCM_SHA256,
			s2apb.Ciphersuite_AES_256_GCM_SHA384,
			s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
		},
		TargetIdentities: []*s2apb.Identity{
			&s2apb.Identity{
				IdentityOneof: &s2apb.Identity_SpiffeId{
					SpiffeId: "target_spiffe_id",
				},
			},
			&s2apb.Identity{
				IdentityOneof: &s2apb.Identity_Hostname{
					Hostname: "target_hostname",
				},
			},
		},
		LocalIdentity: &s2apb.Identity{
			IdentityOneof: &s2apb.Identity_SpiffeId{
				SpiffeId: "client_local_spiffe_id",
			},
		},
		TargetName: "target_name",
	}

	// testServerHandshakerOptions are the server handshaker options used for testing
	testServerHandshakerOptions = &ServerHandshakerOptions{
		MinTLSVersion: s2apb.TLSVersion_TLS1_2,
		MaxTLSVersion: s2apb.TLSVersion_TLS1_3,
		TLSCiphersuites: []s2apb.Ciphersuite{
			s2apb.Ciphersuite_AES_128_GCM_SHA256,
			s2apb.Ciphersuite_AES_256_GCM_SHA384,
			s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
		},
		LocalIdentities: []*s2apb.Identity{
			&s2apb.Identity{
				IdentityOneof: &s2apb.Identity_SpiffeId{
					SpiffeId: "server_local_spiffe_id",
				},
			},
			&s2apb.Identity{
				IdentityOneof: &s2apb.Identity_Hostname{
					Hostname: "server_local_hostname",
				},
			},
		},
	}
)

// fakeStream is a fake implementation of the grpc.ClientStream interface that
// is used for testing.
type fakeStream struct {
	grpc.ClientStream
}

func (*fakeStream) Recv() (*s2apb.SessionResp, error) { return new(s2apb.SessionResp), nil }
func (*fakeStream) Send(*s2apb.SessionReq) error      { return nil }
func (*fakeStream) CloseSend() error                  { return nil }

// fakeConn is a fake implementation of the net.Conn interface that is used for
// testing.
type fakeConn struct {
	net.Conn
	in  *bytes.Buffer
	out *bytes.Buffer
}

func (fc *fakeConn) Read(b []byte) (n int, err error)  { return fc.in.Read(b) }
func (fc *fakeConn) Write(b []byte) (n int, err error) { return fc.out.Write(b) }
func (fc *fakeConn) Close() error                      { return nil }

// fakeInvalidConn is a fake implementation of a invalid net.Conn interface that is
// used for testing.
type fakeInvalidConn struct {
	net.Conn
}

func (fc *fakeInvalidConn) Read(b []byte) (n int, err error)  { return 0, io.EOF }
func (fc *fakeInvalidConn) Write(b []byte) (n int, err error) { return 0, nil }
func (fc *fakeInvalidConn) Close() error                      { return nil }

// MakeFrame creates a handshake frame.
func MakeFrame(pl string) []byte {
	f := make([]byte, len(pl)+4)
	binary.LittleEndian.PutUint32(f, uint32(len(pl)))
	copy(f[4:], []byte(pl))
	return f
}

// TestNewClientHandshaker creates a fake stream, and ensures that
// newClientHandshaker returns a valid client-side handshaker instance.
func TestNewClientHandshaker(t *testing.T) {
	stream := &fakeStream{}
	in := bytes.NewBuffer(MakeFrame("ClientInit"))
	in.Write(MakeFrame("ClientFinished"))
	c := &fakeConn{
		in:  in,
		out: new(bytes.Buffer),
	}
	chs := newClientHandshaker(stream, c, testClientHandshakerOptions)
	if chs.clientOpts != testClientHandshakerOptions || chs.conn != c {
		t.Errorf("handshaker parameters incorrect")
	}
}

// TestNewServerHandshaker creates a fake stream, and ensures that
// newServerHandshaker  returns a valid server-side handshaker instance.
func TestNewServerHandshaker(t *testing.T) {
	stream := &fakeStream{}
	in := bytes.NewBuffer(MakeFrame("ServerInit"))
	in.Write(MakeFrame("ServerFinished"))
	c := &fakeConn{
		in:  in,
		out: new(bytes.Buffer),
	}
	shs := newServerHandshaker(stream, c, testServerHandshakerOptions)
	if shs.serverOpts != testServerHandshakerOptions || shs.conn != c {
		t.Errorf("handshaker parameters incorrect")
	}
}

// TestClienthandshake creates a fake S2A handshaker and performs a client-side
// handshake.
func TestClientHandshake(t *testing.T) {
	errc := make(chan error)
	stream := &fakeStream{}
	in := bytes.NewBuffer(MakeFrame("ClientInit"))
	in.Write(MakeFrame("ClientFinished"))
	c := &fakeConn{
		in:  in,
		out: new(bytes.Buffer),
	}
	chs := &s2aHandshaker{
		stream:     stream,
		conn:       c,
		clientOpts: testClientHandshakerOptions,
	}
	go func() {
		// returned conn is ignored until record Protocol is implemented.
		_, context, err := chs.ClientHandshake(context.Background())
		if err == nil && context == nil {
			panic("expected non-nil S2A context")
		}
		errc <- err
		chs.Close()
	}()
}

// TestServerHandshake creates a fake S2A handshaker and performs a server-side
// handshake.
func TestServerHandshake(t *testing.T) {
	errc := make(chan error)
	stream := &fakeStream{}
	in := bytes.NewBuffer(MakeFrame("ServerInit"))
	in.Write(MakeFrame("ServerFinished"))
	c := &fakeConn{
		in:  in,
		out: new(bytes.Buffer),
	}
	shs := &s2aHandshaker{
		stream:     stream,
		conn:       c,
		serverOpts: testServerHandshakerOptions,
	}
	go func() {
		// returned conn is ignored until record Protocol is implemented.
		_, context, err := shs.ServerHandshake(context.Background())
		if err == nil && context == nil {
			panic("expected non-nil S2A context")
		}
		errc <- err
		shs.Close()
	}()
}

func TestInvalidHandshaker(t *testing.T) {
	emptyHS := &s2aHandshaker{}
	_, _, err := emptyHS.ClientHandshake(context.Background())
	if err == nil {
		t.Error("ClientHandshake() shouldn't work with empty ClientOptions")
	}
	_, _, err = emptyHS.ServerHandshake(context.Background())
	if err == nil {
		t.Error("ServerHandshake() shouldnt' work with empty ServerOptions")
	}
}

// TestPeerNotResponding uses an invalid net.Conn instance and performs a
// handshake to test the case when the peer is not responding.
func TestPeerNotResponding(t *testing.T) {
	stream := &fakeStream{}
	c := &fakeInvalidConn{}
	chs := &s2aHandshaker{
		stream:     stream,
		conn:       c,
		clientOpts: testClientHandshakerOptions,
	}
	_, context, err := chs.ClientHandshake(context.Background())
	chs.Close()
	if context != nil {
		t.Error("expected non-nil S2A context")
	}
	if got, want := err, PeerNotRespondingError; got != want {
		t.Errorf("ClientHandshake() = %v, want %v", got, want)
	}

}
