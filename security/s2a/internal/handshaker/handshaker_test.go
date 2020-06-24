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
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"

	"google.golang.org/grpc"
	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

var (
	// testClientHandshakerOptions are the client-side handshaker options used for testing.
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
		TargetName:               "target_name",
		HandshakerServiceAddress: "client_handshaker_address",
	}

	// testServerHandshakerOptions are the server-side handshaker options used for testing.
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
		HandshakerServiceAddress: "test_server_handshaker_address",
	}

	testClientSessionResult = &s2apb.SessionResult{
		ApplicationProtocol: "grpc",
		State: &s2apb.SessionState{
			TlsVersion:     s2apb.TLSVersion_TLS1_3,
			TlsCiphersuite: s2apb.Ciphersuite_AES_128_GCM_SHA256,
			InSequence:     0,
			OutSequence:    0,
			InKey:          make([]byte, 32),
			OutKey:         make([]byte, 32),
		},
		PeerIdentity: &s2apb.Identity{
			IdentityOneof: &s2apb.Identity_SpiffeId{
				SpiffeId: "client_local_spiffe_id",
			},
		},
		LocalIdentity: &s2apb.Identity{
			IdentityOneof: &s2apb.Identity_SpiffeId{
				SpiffeId: "server_local_spiffe_id",
			},
		},
		LocalCertFingerprint: []byte("client_cert_fingerprint"),
		PeerCertFingerprint:  []byte("server_cert_fingerprint"),
	}

	testServerSessionResult = &s2apb.SessionResult{
		ApplicationProtocol: "grpc",
		State: &s2apb.SessionState{
			TlsVersion:     s2apb.TLSVersion_TLS1_3,
			TlsCiphersuite: s2apb.Ciphersuite_AES_128_GCM_SHA256,
			InSequence:     0,
			OutSequence:    0,
			InKey:          make([]byte, 32),
			OutKey:         make([]byte, 32),
		},
		PeerIdentity: &s2apb.Identity{
			IdentityOneof: &s2apb.Identity_SpiffeId{
				SpiffeId: "server_local_spiffe_id",
			},
		},
		LocalIdentity: &s2apb.Identity{
			IdentityOneof: &s2apb.Identity_SpiffeId{
				SpiffeId: "client_local_spiffe_id",
			},
		},
		LocalCertFingerprint: []byte("server_cert_fingerprint"),
		PeerCertFingerprint:  []byte("client_cert_fingerprint"),
	}
)

// fakeStream is a fake implementation of the grpc.ClientStream interface that
// is used for testing.
type fakeStream struct {
	grpc.ClientStream
	t *testing.T
	// expectedResp is the expected SessionResp message from the handshaker service.
	expectedResp *s2apb.SessionResp
	// isFirstAccess indicates whether the first call to the handshaker service has
	// been made or not.
	isFirstAccess bool
	isClient      bool
}

func (fs *fakeStream) Recv() (*s2apb.SessionResp, error) {
	resp := fs.expectedResp
	fs.expectedResp = nil
	return resp, nil
}
func (fs *fakeStream) Send(req *s2apb.SessionReq) error {
	var resp *s2apb.SessionResp
	if !fs.isFirstAccess {
		// Generate the bytes to be returned by Recv() for the first handshake message.
		fs.isFirstAccess = true
		if fs.isClient {
			resp = &s2apb.SessionResp{
				OutFrames: []byte("ClientHello"),
				// There are no consumed bytes for a client start message
				BytesConsumed: 0,
			}
		} else {
			resp = &s2apb.SessionResp{
				OutFrames: []byte("ServerHello"),
				// Simulate consuming the ClientHello message.
				BytesConsumed: uint32(len("ClientHello")),
			}
		}
	} else {
		// Construct a SessionResp message that contains the handshake result.
		if fs.isClient {
			resp = &s2apb.SessionResp{
				Result: testClientSessionResult,
				// Simulate consuming the ClientFinished message.
				BytesConsumed: uint32(len("ClientFinished")),
			}
		} else {
			resp = &s2apb.SessionResp{
				Result: testServerSessionResult,
				// Simulate consuming the ServerFinished message.
				BytesConsumed: uint32(len("ServerFinished")),
			}
		}

	}
	fs.expectedResp = resp
	return nil
}

func (*fakeStream) CloseSend() error { return nil }

// fakeInvalidStream is a fake implementation of an invalid grpc.ClientStream
// interface that is used for testing.
type fakeInvalidStream struct {
	grpc.ClientStream
}

func (*fakeInvalidStream) Recv() (*s2apb.SessionResp, error) { return &s2apb.SessionResp{}, nil }
func (*fakeInvalidStream) Send(*s2apb.SessionReq) error      { return nil }
func (*fakeInvalidStream) CloseSend() error                  { return nil }

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

// TestNewClientHandshaker creates a fake stream, and ensures that
// newClientHandshaker returns a valid client-side handshaker instance.
func TestNewClientHandshaker(t *testing.T) {
	stream := &fakeStream{}
	in := bytes.NewBuffer([]byte("ClientInit"))
	in.Write([]byte("ClientFinished"))
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
// newServerHandshaker returns a valid server-side handshaker instance.
func TestNewServerHandshaker(t *testing.T) {
	stream := &fakeStream{}
	in := bytes.NewBuffer([]byte("ServerInit"))
	in.Write([]byte("ServerFinished"))
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
	errc := make(chan []error)
	stream := &fakeStream{
		t:        t,
		isClient: true,
	}
	in := bytes.NewBuffer([]byte("ClientHello"))
	in.Write([]byte("ClientFinished"))
	c := &fakeConn{
		in:  in,
		out: new(bytes.Buffer),
	}
	chs := &s2aHandshaker{
		stream:     stream,
		conn:       c,
		clientOpts: testClientHandshakerOptions,
	}
	result := testClientSessionResult
	go func() {
		// Returned conn is ignored until record protocol is implemented.
		errs := []error{}
		newConn, auth, err := chs.ClientHandshake(context.Background())
		errs = append(errs, err)
		if auth.ApplicationProtocol() != result.GetApplicationProtocol() ||
			auth.TLSVersion() != result.GetState().GetTlsVersion() ||
			auth.Ciphersuite() != result.GetState().GetTlsCiphersuite() ||
			auth.PeerIdentity() != result.GetPeerIdentity() ||
			auth.LocalIdentity() != result.GetLocalIdentity() ||
			!bytes.Equal(auth.LocalCertFingerprint(), result.GetLocalCertFingerprint()) ||
			!bytes.Equal(auth.PeerCertFingerprint(), result.GetPeerCertFingerprint()) {
			errs = append(errs, errors.New("Authinfo s2a context incorrect"))
		}
		if reflect.ValueOf(newConn).Elem().Field(0).Interface() != chs.conn {
			errs = append(errs, errors.New("Handshaker netConn incorrect"))
		}
		errc <- errs
		close(errc)
		chs.Close()
	}()

	for _, err := range <-errc {
		if err != nil {
			t.Errorf("%v", err)

		}
	}
}

// TestServerHandshake creates a fake S2A handshaker and performs a server-side
// handshake.
func TestServerHandshake(t *testing.T) {
	errc := make(chan []error)
	stream := &fakeStream{
		t:        t,
		isClient: false,
	}
	in := bytes.NewBuffer([]byte("ServerHello"))
	in.Write([]byte("ServerFinished"))
	c := &fakeConn{
		in:  in,
		out: new(bytes.Buffer),
	}
	shs := &s2aHandshaker{
		stream:     stream,
		conn:       c,
		serverOpts: testServerHandshakerOptions,
	}
	result := testServerSessionResult
	go func() {
		// The conn returned by ServerHandshake is ignored until record protocol
		// is implemented.
		errs := []error{}
		newConn, auth, err := shs.ServerHandshake(context.Background())
		errs = append(errs, err)
		if auth.ApplicationProtocol() != result.GetApplicationProtocol() ||
			auth.TLSVersion() != result.GetState().GetTlsVersion() ||
			auth.Ciphersuite() != result.GetState().GetTlsCiphersuite() ||
			auth.PeerIdentity() != result.GetPeerIdentity() ||
			auth.LocalIdentity() != result.GetLocalIdentity() ||
			!bytes.Equal(auth.LocalCertFingerprint(), result.GetLocalCertFingerprint()) ||
			!bytes.Equal(auth.PeerCertFingerprint(), result.GetPeerCertFingerprint()) {
			errs = append(errs, errors.New("Authinfo s2a context incorrect"))
		}
		if reflect.ValueOf(newConn).Elem().Field(0).Interface() != shs.conn {
			errs = append(errs, fmt.Errorf("Handshaker netConn incorrect:"))
		}
		errc <- errs
		close(errc)
		shs.Close()
	}()

	for _, err := range <-errc {
		if err != nil {
			t.Errorf("%v", err)

		}
	}
}

func TestInvalidHandshaker(t *testing.T) {
	emptyHS := &s2aHandshaker{}
	_, _, err := emptyHS.ClientHandshake(context.Background())
	if err == nil {
		t.Error("ClientHandshake() shouldn't work with empty ClientOptions")
	}
	_, _, err = emptyHS.ServerHandshake(context.Background())
	if err == nil {
		t.Error("ServerHandshake() shouldn't work with empty ServerOptions")
	}
}

// TestPeerNotResponding uses an invalid net.Conn instance and performs a
// client-side handshake to test the case when the peer is not responding.
func TestClientPeerNotResponding(t *testing.T) {
	stream := &fakeInvalidStream{}
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
