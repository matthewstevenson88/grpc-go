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
	"context"
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
					Hostname: "server_local__hostname",
				},
			},
		},
	}
)

// fakeStream is a fake implementation of the grpc.ClientStream interface that
// is used for testing.
type fakeStream struct{ grpc.ClientStream }

func (*fakeStream) Recv() (*s2apb.SessionResp, error) { return new(s2apb.SessionResp), nil }
func (*fakeStream) Send(*s2apb.SessionReq) error      { return nil }

// fakeConn is a fake implementation of the net.Conn interface that is used for
// testing.
type fakeConn struct{ net.Conn }

// TestNewClientHandshaker creates a fake stream, and ensures that
// newClientHandshakerInternal returns a valid client-side handshaker instance.
func TestNewClientHandshaker(t *testing.T) {
	stream := &fakeStream{}
	c := &fakeConn{}
	shs := newClientHandshaker(stream, c, testClientHandshakerOptions)
	if shs.clientOpts != testClientHandshakerOptions || shs.conn != c {
		t.Errorf("handshaker parameters incorrect")
	}
}

// TestNewServerHandshaker creates a fake stream, and ensures that
// newServerHandshakerInternal returns a valid server-side handshaker instance.
func TestNewServerHandshaker(t *testing.T) {
	stream := &fakeStream{}
	c := &fakeConn{}
	shs := newServerHandshaker(stream, c, testServerHandshakerOptions)
	if shs.serverOpts != testServerHandshakerOptions || shs.conn != c {
		t.Errorf("handshaker parameters incorrect")
	}
}

// Test unimplemented methods
func TestProcessUntilDone(t *testing.T) {
	shs := &s2aHandshaker{}
	resp := &s2apb.SessionResp{}
	result, extra, err := shs.processUntilDone(resp, make([]byte, 4))
	if err == nil || result != nil || extra != nil {
		t.Errorf("Method should be unimplemented")
	}
}

func TestAccessHandshakerService(t *testing.T) {
	shs := &s2aHandshaker{}
	req := &s2apb.SessionReq{}
	resp, err := shs.accessHandshakerService(req)
	if err == nil || resp != nil {
		t.Errorf("Method should be unimplemented")
	}
}

func TestSetUpSession(t *testing.T) {
	shs := &s2aHandshaker{}
	req := &s2apb.SessionReq{}
	context, result, err := shs.setUpSession(req)
	if err == nil || context != nil || result != nil {
		t.Errorf("Method should be unimplemented")
	}
}

func TestClientHandshake(t *testing.T) {
	shs := &s2aHandshaker{}
	context, err := shs.ClientHandshake(context.Background())
	if err == nil || context != nil {
		t.Errorf("Method should be unimplemented")
	}
}

func TestServerHandshake(t *testing.T) {
	shs := &s2aHandshaker{}
	context, err := shs.ServerHandshake(context.Background())
	if err == nil || context != nil {
		t.Errorf("Method should be unimplemented")
	}
}
