package authinfo

import (
	"bytes"
	s2a_proto "google.golang.org/grpc/security/s2a/internal/proto"
	"testing"
)

func TestS2AAuthInfo(t *testing.T) {
	for _, tc := range []struct {
		desc                    string
		sessionResult           *s2a_proto.SessionResult
		outAppProtocol          string
		outTLSVersion           s2a_proto.TLSVersion
		outCiphersuite          s2a_proto.Ciphersuite
		outPeerIdentity         *s2a_proto.Identity
		outLocalIdentity        *s2a_proto.Identity
		outPeerCertFingerprint  []byte
		outLocalCertFingerprint []byte
		outErr                  bool
	}{
		{
			desc: "basic 1",
			sessionResult: &s2a_proto.SessionResult{
				ApplicationProtocol: "app protocol",
				State: &s2a_proto.SessionState{
					TlsVersion:     s2a_proto.TLSVersion_TLS1_3,
					TlsCiphersuite: s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
				},
				PeerIdentity: &s2a_proto.Identity{
					IdentityOneof: &s2a_proto.Identity_SpiffeId{
						SpiffeId: "peer spiffe identity",
					},
				},
				LocalIdentity: &s2a_proto.Identity{
					IdentityOneof: &s2a_proto.Identity_Hostname{
						Hostname: "local hostname",
					},
				},
				PeerCertFingerprint:  []byte("peer cert fingerprint"),
				LocalCertFingerprint: []byte("local cert fingerprint"),
			},
			outAppProtocol: "app protocol",
			outTLSVersion:  s2a_proto.TLSVersion_TLS1_3,
			outCiphersuite: s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
			outPeerIdentity: &s2a_proto.Identity{
				IdentityOneof: &s2a_proto.Identity_SpiffeId{
					SpiffeId: "peer spiffe identity",
				},
			},
			outLocalIdentity: &s2a_proto.Identity{
				IdentityOneof: &s2a_proto.Identity_Hostname{
					Hostname: "local hostname",
				},
			},
			outPeerCertFingerprint:  []byte("peer cert fingerprint"),
			outLocalCertFingerprint: []byte("local cert fingerprint"),
		},
		{
			desc: "basic 2",
			sessionResult: &s2a_proto.SessionResult{
				ApplicationProtocol: "app protocol",
				State: &s2a_proto.SessionState{
					TlsVersion:     s2a_proto.TLSVersion_TLS1_2,
					TlsCiphersuite: s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
				},
				PeerIdentity: &s2a_proto.Identity{
					IdentityOneof: &s2a_proto.Identity_Hostname{
						Hostname: "local hostname",
					},
				},
				LocalIdentity: &s2a_proto.Identity{
					IdentityOneof: &s2a_proto.Identity_SpiffeId{
						SpiffeId: "peer spiffe identity",
					},
				},
				PeerCertFingerprint:  []byte("peer cert fingerprint"),
				LocalCertFingerprint: []byte("local cert fingerprint"),
			},
			outAppProtocol: "app protocol",
			outTLSVersion:  s2a_proto.TLSVersion_TLS1_2,
			outCiphersuite: s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
			outPeerIdentity: &s2a_proto.Identity{
				IdentityOneof: &s2a_proto.Identity_Hostname{
					Hostname: "local hostname",
				},
			},
			outLocalIdentity: &s2a_proto.Identity{
				IdentityOneof: &s2a_proto.Identity_SpiffeId{
					SpiffeId: "peer spiffe identity",
				},
			},
			outPeerCertFingerprint:  []byte("peer cert fingerprint"),
			outLocalCertFingerprint: []byte("local cert fingerprint"),
		},
		{
			desc: "nil identities and fingerprints",
			sessionResult: &s2a_proto.SessionResult{
				ApplicationProtocol: "app protocol",
				State: &s2a_proto.SessionState{
					TlsVersion:     s2a_proto.TLSVersion_TLS1_3,
					TlsCiphersuite: s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
				},
			},
			outAppProtocol: "app protocol",
			outTLSVersion:  s2a_proto.TLSVersion_TLS1_3,
			outCiphersuite: s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
		},
		{
			desc:   "nil session result",
			outErr: true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			authInfo, err := NewS2AAuthInfo(tc.sessionResult)
			if got, want := err == nil, !tc.outErr; got != want {
				t.Errorf("NewS2AAuthInfo(%v) = (err=nil) = %v, want %v", tc.sessionResult, got, want)
			}
			if err == nil {
				if got, want := authInfo.AuthType(), s2aAuthType; got != want {
					t.Errorf("authInfo.AuthType() = %v, want %v", got, want)
				}
				if got, want := authInfo.ApplicationProtocol(), tc.outAppProtocol; got != want {
					t.Errorf("authInfo.ApplicationProtocol() = %v, want %v", got, want)
				}
				if got, want := authInfo.TLSVersion(), tc.outTLSVersion; got != want {
					t.Errorf("authInfo.TLSVersion() = %v, want %v", got, want)
				}
				if got, want := authInfo.Ciphersuite(), tc.outCiphersuite; got != want {
					t.Errorf("authInfo.Ciphersuite() = %v, want %v", got, want)
				}
				if got, want := authInfo.PeerIdentity().String(), tc.outPeerIdentity.String(); got != want {
					t.Errorf("authInfo.PeerIdentity() = %v, want %v", got, want)
				}
				if got, want := authInfo.LocalIdentity().String(), tc.outLocalIdentity.String(); got != want {
					t.Errorf("authInfo.LocalIdentity() = %v, want %v", got, want)
				}
				if got, want := authInfo.PeerCertFingerprint(), tc.outPeerCertFingerprint; !bytes.Equal(got, want) {
					t.Errorf("authinfo.PeerCertFingerprint() = %v, want %v", got, want)
				}
				if got, want := authInfo.LocalCertFingerprint(), tc.outLocalCertFingerprint; !bytes.Equal(got, want) {
					t.Errorf("authinfo.LocalCertFingerprint() = %v, want %v", got, want)
				}
			}
		})
	}
}
