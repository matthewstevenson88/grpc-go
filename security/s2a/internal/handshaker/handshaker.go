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

	grpc "google.golang.org/grpc"
	s2a "google.golang.org/grpc/security/s2a/internal/proto"
)

// ClientHandshakerOptions contains the options needed to configure the S2A
// handshaker service on the client-side.
type ClientHandshakerOptions struct {
	// LocalIdentity is the local identity of the client
	// application. If none is provided, then the S2A will choose a default
	// identity.
	LocalIdentity *s2a.Identity
	// TargetName is the allowed server name, which may be used for server
	// authorization check by the S2A if it is provided.
	TargetName string
	// TargetIdentities contains a list of allowed server identities. One of
	// the target identities should match the perr identity in the handshake
	// result; otherwise, the handshake failes.
	TargetIdentities []*s2a.Identity
	// MinTLSVersion and MaxTLSVersion specify the min and max TLS versions
	// supported by the client.
	MinTLSVersion s2a.TLSVersion
	MaxTLSVersion s2a.TLSVersion
	// The ordered list of ciphersuites supported by the client.
	SupportedCiphersuiteList []s2a.Ciphersuite
}

// ServerHandshakerOptions contains the options needed to configure the S2A
// handshaker service on the server-side.
type ServerHandshakerOptions struct {
	// MinTLSVersion and MaxTLSVersion specify the min and max TLS versions
	// supported by the server.
	MinTLSVersion s2a.TLSVersion
	MaxTLSVersion s2a.TLSVersion
	// The local identities that may be assumed by the server. If no local
	// identity is specified, then the S2A chooses a default local identity.
	LocalIdentities []*s2a.Identity
	// The ordered list of ciphersuites supported by the server.
	SupportedCiphersuiteList []s2a.Ciphersuite
}

// s2aHandshaker performs a TLS handshake using the S2A handshaker service.
type s2aHandshaker struct {
	// Stream used to communicate with the S2A handshaker service.
	stream s2a.S2AService_SetUpSessionClient
	// The connection to the peer.
	conn net.Conn
	// clientOpts should be non-nil iff isClient is true, and serverOpts
	// should be non-nil iff isClient is false
	clientOpts *ClientHandshakerOptions
	serverOpts *ServerHandshakerOptions
	isClient   bool
}

// NewClientHandshaker creates an s2aHandshaker instance that performs a
// client-side TLS handshake using the S2A handshaker service.
func NewClientHandshaker(ctx context.Context, conn *grpc.ClientConn, c net.Conn, opts *ClientHandshakerOptions) (*s2aHandshaker, error) {
	stream, err := s2a.NewS2AServiceClient(conn).SetUpSession(ctx, grpc.WaitForReady(true))
	if err != nil {
		return nil, err
	}
	return newClientHandshakerInternal(stream, c, opts), err
}

// newClientHandshakerInternal is for testing purposes only.
func newClientHandshakerInternal(stream s2a.S2AService_SetUpSessionClient, c net.Conn, opts *ClientHandshakerOptions) *s2aHandshaker {
	return &s2aHandshaker{
		stream:     stream,
		conn:       c,
		clientOpts: opts,
		isClient:   true,
	}
}

// NewServerHandshaker creates an s2aHandshaker instance that performs a
// server-side TLS handshake using the S2A handshaker service.
func NewServerHandshaker(ctx context.Context, conn *grpc.ClientConn, c net.Conn, opts *ServerHandshakerOptions) (*s2aHandshaker, error) {
	stream, err := s2a.NewS2AServiceClient(conn).SetUpSession(ctx, grpc.WaitForReady(true))
	if err != nil {
		return nil, err
	}
	return newServerHandshakerInternal(stream, c, opts), err
}

// newClientHandshakerInternal is for testing purposes only.
func newServerHandshakerInternal(stream s2a.S2AService_SetUpSessionClient, c net.Conn, opts *ServerHandshakerOptions) *s2aHandshaker {
	return &s2aHandshaker{
		stream:     stream,
		conn:       c,
		serverOpts: opts,
		isClient:   false,
	}
}

// ClientHandshake performs a client-side TLS handshake using the S2A handshaker
// service. When complete, returns a secure TLS connection.
func (h *s2aHandshaker) ClientHandshake(ctx context.Context) (net.Conn, error) {
	return nil, errors.New("Method unimplemented")
}

// ServerHandshake performs a server-side TLS handshake using the S2A handshaker
// service. When complete, returns a secure TLS connection.
func (h *s2aHandshaker) ServerHandshake(ctx context.Context) (net.Conn, error) {
	return nil, errors.New("Method unimplemented")
}

func (h *s2aHandshaker) setUpSession(req *s2a.SessionReq) (net.Conn, *s2a.SessionResult, error) {
	return nil, nil, errors.New("Method unimplemented")
}

func (h *s2aHandshaker) accessHandshakerService(req *s2a.SessionReq) (*s2a.SessionResp, error) {
	return nil, errors.New("Method unimplemented")
}

func (h *s2aHandshaker) processUntilDone(resp *s2a.SessionResp, extra []byte) (*s2a.SessionResult, []byte, error) {
	return nil, nil, errors.New("Method unimplemented")
}

// Close shuts down the handshaker and the stream to the S2A handshaker service
// when the handshake is complete. It should be called when the caller obtains
// the secure connection at the end of the handshake; otherwise, it is a no-op.
func (h *s2aHandshaker) Close() {
	// Method is unimplemented.
}
