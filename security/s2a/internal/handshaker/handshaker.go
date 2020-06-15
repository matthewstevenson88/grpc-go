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

// Package handshaker provides S2A handshaking functionality for GCP.
package handshaker

import (
	"context"
	"net"

	grpc "google.golang.org/grpc"
	s2a "google.golang.org/grpc/security/s2a/internal/proto"
)

const ()

var ()

func init() {
}

func acquire() bool {
	return false
}

func release() {
}

// ClientHandshakerOptions contains the client handshaker options that are
// provided by the caller.
type ClientHandshakerOptions struct {
	// ClientIdentity is the handshaker client local identity.
	ClientIdentity *s2a.Identity
	// TargetName is the server service account name for secure name
	// checking.
	TargetName string
	// TargetServiceAccounts contains a list of expected target service
	// accounts. One of these accounts should match one of the accounts in
	// the handshaker results. Otherwise, the handshake fails.
	TargetIdentities []*s2a.Identity
	// RPCVersions specifies the gRPC versions accepted by the client.
	TLSVersion *s2a.TLSVersion
	// TODO: determine a graceful method of providing Hostname OR SpiffeID
	Hostname string
	SpiffeID string
	// Cipher specifies the ciphersuite supported by the client
	Cipher *s2a.Ciphersuite
}

// ServerHandshakerOptions contains the server handshaker options that are
// provided by the caller.
type ServerHandshakerOptions struct {
	// TLSVersion specifies the TLS versions accepted by the server.
	TLSVersion *s2a.TLSVersion
	// TODO: determine a graceful method of providing Hostname or SpiffeID
	Hostname string
	SpiffeID string
	// Cipher specifies the ciphersuite supported by the server.
	Cipher *s2a.Ciphersuite
}

// s2aHandshaker is used to complete a S2A handshaking between client and
// server. This handshaker talks to the S2A  handshaker service in the metadata
// server.
type s2aHandshaker struct {
	// RPC stream used to access the S2A Handshaker service.
	stream s2a.S2AService_SetUpSessionClient
	// the connection to the peer.
	conn net.Conn
	// client handshake options.
	clientOpts *ClientHandshakerOptions
	// server handshake options.
	serverOpts *ServerHandshakerOptions
}

// NewClientHandshaker creates a S2A client handshaker to talk to the S2A server
// handshaker service.
func NewClientHandshaker(ctx context.Context, conn *grpc.ClientConn, c net.Conn, opts *ClientHandshakerOptions) (*s2aHandshaker, error) {
	return &s2aHandshaker{}, nil
}

// NewServerHandshaker creates a S2A server handshaker to talk to the S2A client
// handshaker service.
func NewServerHandshaker(ctx context.Context, conn *grpc.ClientConn, c net.Conn, opts *ServerHandshakerOptions) (*s2aHandshaker, error) {
	return &s2aHandshaker{}, nil
}

// ClientHandshake starts and completes a client handshaking for GCP. Once
// done, ClientHandshake returns a secure connection.
func (h *s2aHandshaker) ClientHandshake(ctx context.Context) (net.Conn, error) {
	return nil, nil
}

// ServerHandshake starts and completes a server handshaking for GCP. Once
// done, ServerHandshake returns a secure connection.
func (h *s2aHandshaker) ServerHandshake(ctx context.Context) (net.Conn, error) {
	return nil, nil
}

func (h *s2aHandshaker) doHandshake(req *s2a.SessionReq) (net.Conn, *s2a.SessionResult, error) {
	return nil, nil, nil
}

func (h *s2aHandshaker) accessHandshakerService(req *s2a.SessionReq) (*s2a.SessionResp, error) {
	return nil, nil
}

// processUntilDone processes the handshake until the handshaker service returns
// the results. Handshaker service takes care of frame parsing, so we read
// whatever received from the network and send it to the handshaker service.
func (h *s2aHandshaker) processUntilDone(resp *s2a.SessionResp, extra []byte) (*s2a.SessionResult, []byte, error) {
	return nil, nil, nil
}

// Close terminates the Handshaker. It should be called when the caller obtains
// the secure connection.
func (h *s2aHandshaker) Close() {
}
