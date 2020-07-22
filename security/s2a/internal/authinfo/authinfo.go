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

/*
Package authinfo provides authentication and authorization information from the
S2A session result to the gRPC stack.
*/
package authinfo

import (
	"errors"

	"google.golang.org/grpc/credentials"
	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

const s2aAuthType = "s2a"

// S2AAuthInfo exposes authentication and authorization information from the
// S2A session result to the gRPC stack.
type S2AAuthInfo struct {
	credentials.CommonAuthInfo
	s2aContext *s2apb.S2AContext
}

// NewS2aAuthInfo returns a new S2AAuthInfo object from the S2A session result.
func NewS2AAuthInfo(result *s2apb.SessionResult) (*S2AAuthInfo, error) {
	if result == nil {
		return nil, errors.New("NewS2aAuthInfo given nil session result")
	}
	return &S2AAuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		s2aContext: &s2apb.S2AContext{
			ApplicationProtocol:  result.GetApplicationProtocol(),
			TlsVersion:           result.GetState().GetTlsVersion(),
			Ciphersuite:          result.GetState().GetTlsCiphersuite(),
			PeerIdentity:         result.GetPeerIdentity(),
			LocalIdentity:        result.GetLocalIdentity(),
			PeerCertFingerprint:  result.GetPeerCertFingerprint(),
			LocalCertFingerprint: result.GetLocalCertFingerprint(),
		},
	}, nil
}

// AuthType returns the authentication type.
func (s *S2AAuthInfo) AuthType() string {
	return s2aAuthType
}

// ApplicationProtocol returns the application protocol, e.g. "grpc".
func (s *S2AAuthInfo) ApplicationProtocol() string {
	return s.s2aContext.GetApplicationProtocol()
}

// TLSVersion returns the TLS version negotiated during the handshake.
func (s *S2AAuthInfo) TLSVersion() s2apb.TLSVersion {
	return s.s2aContext.GetTlsVersion()
}

// Ciphersuite returns the ciphersuite negotiated during the handshake.
func (s *S2AAuthInfo) Ciphersuite() s2apb.Ciphersuite {
	return s.s2aContext.GetCiphersuite()
}

// PeerIdentity returns the authenticated identity of the peer.
func (s *S2AAuthInfo) PeerIdentity() *s2apb.Identity {
	return s.s2aContext.GetPeerIdentity()
}

// LocalIdentity returns the local identity of the application used during
// session setup.
func (s *S2AAuthInfo) LocalIdentity() *s2apb.Identity {
	return s.s2aContext.GetLocalIdentity()
}

// PeerCertFingerprint returns the SHA256 hash of the peer certificate used in
// the S2A handshake.
func (s *S2AAuthInfo) PeerCertFingerprint() []byte {
	return s.s2aContext.GetPeerCertFingerprint()
}

// LocalCertFingerprint returns the SHA256 hash of the local certificate used
// in the S2A handshake.
func (s *S2AAuthInfo) LocalCertFingerprint() []byte {
	return s.s2aContext.GetLocalCertFingerprint()
}
