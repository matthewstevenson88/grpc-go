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
	"errors"
	"net"

	"google.golang.org/grpc"
	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

// ClientHandshakerOptions contains the options needed to configure the S2A
// handshaker service on the client-side.
type ClientHandshakerOptions struct {
	// MinTLSVersion specifies the min TLS version supported by the client.
	MinTLSVersion s2apb.TLSVersion
	// MaxTLSVersion specifies the max TLS version supported by the client.
	MaxTLSVersion s2apb.TLSVersion
	// The ordered list of ciphersuites supported by the client.
	TLSCiphersuites []s2apb.Ciphersuite
	// TargetIdentities contains a list of allowed server identities. One of the
	// target identities should match the peer identity in the handshake
	// result; otherwise, the handshake fails.
	TargetIdentities []*s2apb.Identity
	// LocalIdentity is the local identity of the client application. If none is
	// provided, then the S2A will choose the default identity.
	LocalIdentity *s2apb.Identity
	// TargetName is the allowed server name, which may be used for server
	// authorization check by the S2A if it is provided.
	TargetName string
}

// ServerHandshakerOptions contains the options needed to configure the S2A
// handshaker service on the server-side.
type ServerHandshakerOptions struct {
	// MinTLSVersion specifies the min TLS version supported by the server.
	MinTLSVersion s2apb.TLSVersion
	// MaxTLSVersion specifies the max TLS version supported by the server.
	MaxTLSVersion s2apb.TLSVersion
	// The ordered list of ciphersuites supported by the server.
	TLSCiphersuites []s2apb.Ciphersuite
	// The local identities that may be assumed by the server. If no local
	// identity is specified, then the S2A chooses a default local identity.
	LocalIdentities []*s2apb.Identity
}

// s2aHandshaker performs a TLS handshake using the S2A handshaker service.
type s2aHandshaker struct {
	// Stream used to communicate with the S2A handshaker service.
	stream s2apb.S2AService_SetUpSessionClient
	// The connection to the peer.
	conn net.Conn
	// clientOpts should be non-nil iff the handshaker is client-side.
	clientOpts *ClientHandshakerOptions
	// serverOpts should be non-nil iff the handshaker is server-side.
	serverOpts *ServerHandshakerOptions
}

// NewClientHandshaker creates an s2aHandshaker instance that performs a
// client-side TLS handshake using the S2A handshaker service.
func NewClientHandshaker(ctx context.Context, conn *grpc.ClientConn, c net.Conn, opts *ClientHandshakerOptions) (*s2aHandshaker, error) {
	stream, err := s2apb.NewS2AServiceClient(conn).SetUpSession(ctx, grpc.WaitForReady(true))
	if err != nil {
		return nil, err
	}
	return newClientHandshaker(stream, c, opts), err
}

// newClientHandshakerInternal is for testing purposes only.
func newClientHandshaker(stream s2apb.S2AService_SetUpSessionClient, c net.Conn, opts *ClientHandshakerOptions) *s2aHandshaker {
	return &s2aHandshaker{
		stream:     stream,
		conn:       c,
		clientOpts: opts,
	}
}

// NewServerHandshaker creates an s2aHandshaker instance that performs a
// server-side TLS handshake using the S2A handshaker service.
func NewServerHandshaker(ctx context.Context, conn *grpc.ClientConn, c net.Conn, opts *ServerHandshakerOptions) (*s2aHandshaker, error) {
	stream, err := s2apb.NewS2AServiceClient(conn).SetUpSession(ctx, grpc.WaitForReady(true))
	if err != nil {
		return nil, err
	}
	return newServerHandshaker(stream, c, opts), err
}

// newClientHandshakerInternal is for testing purposes only.
func newServerHandshaker(stream s2apb.S2AService_SetUpSessionClient, c net.Conn, opts *ServerHandshakerOptions) *s2aHandshaker {
	return &s2aHandshaker{
		stream:     stream,
		conn:       c,
		serverOpts: opts,
	}
}

// ClientHandshake performs a client-side TLS handshake using S2A. When complete,
// it returns a TLS connection.
func (h *s2aHandshaker) ClientHandshake(ctx context.Context) (net.Conn, error) {
	return nil, errors.New("Method unimplemented")
}

// ServerHandshake performs a server-side TLS handshake using the S2A handshaker
// service. When complete, returns a secure TLS connection.
func (h *s2aHandshaker) ServerHandshake(ctx context.Context) (net.Conn, error) {
	return nil, errors.New("Method unimplemented")
}

func (h *s2aHandshaker) setUpSession(req *s2apb.SessionReq) (net.Conn, *s2apb.SessionResult, error) {
	return nil, nil, errors.New("Method unimplemented")
}

func (h *s2aHandshaker) accessHandshakerService(req *s2apb.SessionReq) (*s2apb.SessionResp, error) {
	return nil, errors.New("Method unimplemented")
}

func (h *s2aHandshaker) processUntilDone(resp *s2apb.SessionResp, extra []byte) (*s2apb.SessionResult, []byte, error) {
	return nil, nil, errors.New("Method unimplemented")
}

func (h *s2aHandshaker) Close() {
	// Method is unimplemented.
}
