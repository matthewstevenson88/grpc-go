/*
 *
 * Copyright 2018 gRPC authors.
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
	"testing"

	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/security/s2a/internal/handshaker/testutil"
	s2a "google.golang.org/grpc/security/s2a/internal/proto"
)

var (
	// testClientHandshakerOptions are the client handshaker options used
	// for testing.
	testClientHandshakerOptions = &ClientHandshakerOptions{
		ClientIdentity: &s2a.Identity{
			IdentityOneof: &s2a.Identity_SpiffeId{
				SpiffeId: "spiffe_id",
			},
		},
		TargetName: "target_name",
		TargetIdentities: []*s2a.Identity{
			&s2a.Identity{
				IdentityOneof: &s2a.Identity_SpiffeId{
					SpiffeId: "target_spiffe_id",
				},
			},
			&s2a.Identity{
				IdentityOneof: &s2a.Identity_Hostname{
					Hostname: "target_hostname",
				},
			},
		},
		MinTLSVersion: s2a.TLSVersion_TLS1_2,
		MaxTLSVersion: s2a.TLSVersion_TLS1_3,
		SupportedCiphersuiteList: []s2a.Ciphersuite{
			s2a.Ciphersuite_AES_128_GCM_SHA256,
			s2a.Ciphersuite_AES_256_GCM_SHA384,
			s2a.Ciphersuite_CHACHA20_POLY1305_SHA256,
		},
	}

	// testServerHandshakerOptions are the server handshaker options used
	// for testing.
	testServerHandshakerOptions = &ServerHandshakerOptions{
		LocalIdentities: []*s2a.Identity{
			&s2a.Identity{
				IdentityOneof: &s2a.Identity_SpiffeId{
					SpiffeId: "local_spiffe_id",
				},
			},
			&s2a.Identity{
				IdentityOneof: &s2a.Identity_Hostname{
					Hostname: "target_hostname",
				},
			},
		},
		MinTLSVersion: s2a.TLSVersion_TLS1_2,
		MaxTLSVersion: s2a.TLSVersion_TLS1_3,
		SupportedCiphersuiteList: []s2a.Ciphersuite{
			s2a.Ciphersuite_AES_128_GCM_SHA256,
			s2a.Ciphersuite_AES_256_GCM_SHA384,
			s2a.Ciphersuite_CHACHA20_POLY1305_SHA256,
		},
	}
)

// fakeStream is a fake implementation of a Client Stream used for testing.
type fakeStream struct{ grpc.ClientStream }

func (*fakeStream) Recv() (*s2a.SessionResp, error) { return new(s2a.SessionResp), nil }
func (*fakeStream) Send(*s2a.SessionReq) error      { return nil }

// TestNewClientHandshaker creates a fake stream, and ensures that
// newClientHandshakerInternal returns a valid client-side handshaker instance.
func TestNewClientHandshaker(t *testing.T) {
	stream := &fakeStream{}
	f1 := testutil.MakeFrame("ClientInit")
	f2 := testutil.MakeFrame("ClientFinished")
	in := bytes.NewBuffer(f1)
	in.Write(f2)
	out := new(bytes.Buffer)
	c := testutil.NewTestConn(in, out)
	shs := newClientHandshakerInternal(stream, c, testClientHandshakerOptions)
	if !shs.isClient || shs.clientOpts != testClientHandshakerOptions || shs.conn != c {
		t.Errorf("handshaker parameters incorrect")
	}
}

// TestNewServerHandshaker creates a fake stream, and ensures that
// newServerHandshakerInternal returns a valid server-side handshaker instance.
func TestNewServerHandshaker(t *testing.T) {
	stream := &fakeStream{}
	f1 := testutil.MakeFrame("ServerInit")
	f2 := testutil.MakeFrame("ServerFinished")
	in := bytes.NewBuffer(f1)
	in.Write(f2)
	out := new(bytes.Buffer)
	c := testutil.NewTestConn(in, out)
	shs := newServerHandshakerInternal(stream, c, testServerHandshakerOptions)
	if shs.isClient || shs.serverOpts != testServerHandshakerOptions || shs.conn != c {
		t.Errorf("handshaker parameters incorrect")
	}
}

// Test unimplemented Methods
func TestProcessUntilDone(t *testing.T) {
	shs := &s2aHandshaker{}
	resp := &s2a.SessionResp{}
	result, extra, err := shs.processUntilDone(resp, make([]byte, 4))
	if err == nil || result != nil || extra != nil {
		t.Errorf("Method should be unimplemented")
	}
}

func TestAccessHandshakerService(t *testing.T) {
	shs := &s2aHandshaker{}
	req := &s2a.SessionReq{}
	resp, err := shs.accessHandshakerService(req)
	if err == nil || resp != nil {
		t.Errorf("Method should be unimplemented")
	}
}

func TestSetUpSession(t *testing.T) {
	shs := &s2aHandshaker{}
	req := &s2a.SessionReq{}
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
		t.Errorf("Method is supposed to be unimplemented")
	}
}
