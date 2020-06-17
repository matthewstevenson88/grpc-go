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
	"fmt"
	"io"
	"net"

	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/security/s2a/internal/authinfo"
	s2a "google.golang.org/grpc/security/s2a/internal/proto"
)

var (
	appProtocols = []string{"grpc"}
	frameLimit   = 1024 * 128
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
	// the target identities should match the peer identity in the handshake
	// result; otherwise, the handshake fails.
	TargetIdentities []*s2a.Identity
	// MinTLSVersion and MaxTLSVersion specify the min and max TLS versions
	// supported by the client.
	MinTlsVersion s2a.TLSVersion
	MaxTlsVersion s2a.TLSVersion
	// The ordered list of ciphersuites supported by the client.
	SupportedCiphersuiteList []s2a.Ciphersuite
}

// ServerHandshakerOptions contains the options needed to configure the S2A
// handshaker service on the server-side.
type ServerHandshakerOptions struct {
	// MinTLSVersion and MaxTLSVersion specify the min and max TLS versions
	// supported by the server.
	MinTlsVersion s2a.TLSVersion
	MaxTlsVersion s2a.TLSVersion
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
	// should be non-nil iff isClient is false.
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
func (h *s2aHandshaker) ClientHandshake(ctx context.Context) (net.Conn, *authinfo.S2AAuthInfo, error) {
	if !h.isClient {
		return nil, nil, errors.New("only handshakers created using NewClientHandshaker can perform a client handshaker")
	}

	// Create target identities from service account list.
	req := &s2a.SessionReq{
		ReqOneof: &s2a.SessionReq_ClientStart{
			ClientStart: &s2a.ClientSessionStartReq{
				ApplicationProtocols: appProtocols,
				MinTlsVersion:        h.clientOpts.MinTlsVersion,
				MaxTlsVersion:        h.clientOpts.MaxTlsVersion,
				TlsCiphersuites:      h.clientOpts.SupportedCiphersuiteList,
				TargetIdentities:     h.clientOpts.TargetIdentities,
				LocalIdentity:        h.clientOpts.LocalIdentity,
				TargetName:           h.clientOpts.TargetName,
			},
		},
	}

	conn, result, err := h.setUpSession(req)
	if err != nil {
		return nil, nil, err
	}
	authInfo, err := authinfo.NewS2AAuthInfo(result)
	if err != nil {
		return nil, nil, err
	}
	return conn, authInfo, nil
}

// ServerHandshake performs a server-side TLS handshake using the S2A handshaker
// service. When complete, returns a secure TLS connection.
func (h *s2aHandshaker) ServerHandshake(ctx context.Context) (net.Conn, *authinfo.S2AAuthInfo, error) {

	if h.isClient {
		return nil, nil, errors.New("only handshakers created using NewServerHandshaker can perform a server handshaker")
	}

	p := make([]byte, 64*1024) // temp length?
	n, err := h.conn.Read(p)
	if err != nil {
		return nil, nil, err
	}
	req := &s2a.SessionReq{
		ReqOneof: &s2a.SessionReq_ServerStart{
			ServerStart: &s2a.ServerSessionStartReq{
				ApplicationProtocols: appProtocols,
				MinTlsVersion:        h.serverOpts.MinTlsVersion,
				MaxTlsVersion:        h.serverOpts.MaxTlsVersion,
				TlsCiphersuites:      h.serverOpts.SupportedCiphersuiteList,
				LocalIdentities:      h.serverOpts.LocalIdentities,
				InBytes:              p[:n],
			},
		},
	}

	conn, result, err := h.setUpSession(req)
	if err != nil {
		return nil, nil, err
	}
	authInfo, err := authinfo.NewS2AAuthInfo(result)
	if err != nil {
		return nil, nil, err
	}
	return conn, authInfo, nil
}

func (h *s2aHandshaker) setUpSession(req *s2a.SessionReq) (net.Conn, *s2a.SessionResult, error) {
	resp, err := h.accessHandshakerService(req)
	if err != nil {
		return nil, nil, err
	}
	// Check if the returned status is an error.
	if resp.GetStatus() != nil {
		if got, want := resp.GetStatus().Code, uint32(codes.OK); got != want {
			return nil, nil, fmt.Errorf("%v", resp.GetStatus().Details)
		}
	}

	var extra []byte
	if req.GetServerStart() != nil {
		if resp.GetBytesConsumed() > uint32(len(req.GetServerStart().GetInBytes())) {
			return nil, nil, errors.New("handshaker service consumed bytes value is out-of-bound")
		}
		extra = req.GetServerStart().GetInBytes()[resp.GetBytesConsumed():]
	}
	result, extra, err := h.processUntilDone(resp, extra)
	if err != nil {
		return nil, nil, err
	}
	// TODO: implemented record protocol & new Conn
	return h.conn, result, nil
}

func (h *s2aHandshaker) accessHandshakerService(req *s2a.SessionReq) (*s2a.SessionResp, error) {
	if err := h.stream.Send(req); err != nil {
		return nil, err
	}
	resp, err := h.stream.Recv()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// processUntilDone processes the handshake until the handshaker service returns
// the results.
func (h *s2aHandshaker) processUntilDone(resp *s2a.SessionResp, extra []byte) (*s2a.SessionResult, []byte, error) {
	for {
		if len(resp.OutFrames) > 0 {
			if _, err := h.conn.Write(resp.OutFrames); err != nil {
				return nil, nil, err
			}
		}
		if resp.Result != nil {
			return resp.Result, extra, nil
		}
		buf := make([]byte, frameLimit)
		n, err := h.conn.Read(buf)
		if err != nil && err != io.EOF {
			return nil, nil, err
		}
		// If there is nothing to send to the handshaker service, and
		// nothing is received from the peer, then we are stuck.
		// This covers the case when the peer is not responding. Note
		// that handshaker service connection issues are caught in
		// accessHandshakerService before we even get here.
		if len(resp.OutFrames) == 0 && n == 0 {
			return nil, nil, errors.New("peer server is not responding and re-connection should be attempted")
		}
		// Append extra bytes from the previous interaction with the
		// handshaker service with the current buffer read from conn.
		p := append(extra, buf[:n]...)
		// From here on, p and extra point to the same slice.
		resp, err = h.accessHandshakerService(&s2a.SessionReq{
			ReqOneof: &s2a.SessionReq_Next{
				Next: &s2a.SessionNextReq{
					InBytes: p,
				},
			},
		})
		if err != nil {
			return nil, nil, err
		}
		// Set extra based on handshaker service response.
		if resp.GetBytesConsumed() > uint32(len(p)) {
			return nil, nil, errors.New("handshaker service consumed bytes value is out-of-bound")
		}
		extra = p[resp.GetBytesConsumed():]
	}
}

// Close shuts down the handshaker and the stream to the S2A handshaker service
// when the handshake is complete. It should be called when the caller obtains
// the secure connection at the end of the handshake; otherwise it is a no-op.
func (h *s2aHandshaker) Close() {
	h.stream.CloseSend()
}
