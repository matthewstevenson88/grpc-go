package authinfo

import (
	"google.golang.org/grpc/credentials"
	s2a_proto "google.golang.org/grpc/security/s2a/internal/proto"
)

// S2AAuthInfo exposes authentication information from the S2A session results
// to the application.
type S2AAuthInfo struct {
	s2aContext *s2a_proto.S2AContext
	credentials.CommonAuthInfo
}

// NewS2aAuthInfo returns a new S2AAuthInfo object given the S2A session
// results.
func NewS2AAuthInfo(result *s2a_proto.SessionResult) *S2AAuthInfo {
	return &S2AAuthInfo{
		s2aContext: &s2a_proto.S2AContext{
			ApplicationProtocol:  result.GetApplicationProtocol(),
			TlsVersion:           result.GetState().GetTlsVersion(),
			Ciphersuite:          result.GetState().GetTlsCiphersuite(),
			PeerIdentity:         result.GetPeerIdentity(),
			LocalIdentity:        result.GetLocalIdentity(),
			PeerCertFingerprint:  result.GetPeerCertFingerprint(),
			LocalCertFingerprint: result.GetLocalCertFingerprint(),
		},
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
	}
}

// AuthType returns the authentication type.
func (s *S2AAuthInfo) AuthType() string {
	return "s2a"
}

// ApplicationProtocol returns the application protocol.
func (s *S2AAuthInfo) ApplicationProtocol() string {
	return s.s2aContext.GetApplicationProtocol()
}

// TLSVersion returns the TLS version.
func (s *S2AAuthInfo) TLSVersion() s2a_proto.TLSVersion {
	return s.s2aContext.GetTlsVersion()
}

// Ciphersuite returns the ciphersuite.
func (s *S2AAuthInfo) Ciphersuite() s2a_proto.Ciphersuite {
	return s.s2aContext.GetCiphersuite()
}

// PeerIdentity returns the authenticated identity of the peer.
func (s *S2AAuthInfo) PeerIdentity() *s2a_proto.Identity {
	return s.s2aContext.GetPeerIdentity()
}

// LocalIdentity returns the local identity used during session setup.
func (s *S2AAuthInfo) LocalIdentity() *s2a_proto.Identity {
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
