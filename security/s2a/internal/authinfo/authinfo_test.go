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

package authinfo

import (
	"bytes"
	"testing"

	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

func TestS2AAuthInfo(t *testing.T) {
	for _, tc := range []struct {
		desc                    string
		sessionResult           *s2apb.SessionResult
		outAppProtocol          string
		outTLSVersion           s2apb.TLSVersion
		outCiphersuite          s2apb.Ciphersuite
		outPeerIdentity         *s2apb.Identity
		outLocalIdentity        *s2apb.Identity
		outPeerCertFingerprint  []byte
		outLocalCertFingerprint []byte
		outErr                  bool
	}{
		{
			desc: "basic 1",
			sessionResult: &s2apb.SessionResult{
				ApplicationProtocol: "app protocol",
				State: &s2apb.SessionState{
					TlsVersion:     s2apb.TLSVersion_TLS1_3,
					TlsCiphersuite: s2apb.Ciphersuite_AES_128_GCM_SHA256,
				},
				PeerIdentity: &s2apb.Identity{
					IdentityOneof: &s2apb.Identity_SpiffeId{
						SpiffeId: "peer spiffe identity",
					},
				},
				LocalIdentity: &s2apb.Identity{
					IdentityOneof: &s2apb.Identity_Hostname{
						Hostname: "local hostname",
					},
				},
				PeerCertFingerprint:  []byte("peer cert fingerprint"),
				LocalCertFingerprint: []byte("local cert fingerprint"),
			},
			outAppProtocol: "app protocol",
			outTLSVersion:  s2apb.TLSVersion_TLS1_3,
			outCiphersuite: s2apb.Ciphersuite_AES_128_GCM_SHA256,
			outPeerIdentity: &s2apb.Identity{
				IdentityOneof: &s2apb.Identity_SpiffeId{
					SpiffeId: "peer spiffe identity",
				},
			},
			outLocalIdentity: &s2apb.Identity{
				IdentityOneof: &s2apb.Identity_Hostname{
					Hostname: "local hostname",
				},
			},
			outPeerCertFingerprint:  []byte("peer cert fingerprint"),
			outLocalCertFingerprint: []byte("local cert fingerprint"),
		},
		{
			desc: "basic 2",
			sessionResult: &s2apb.SessionResult{
				ApplicationProtocol: "app protocol",
				State: &s2apb.SessionState{
					TlsVersion:     s2apb.TLSVersion_TLS1_2,
					TlsCiphersuite: s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
				},
				PeerIdentity: &s2apb.Identity{
					IdentityOneof: &s2apb.Identity_Hostname{
						Hostname: "local hostname",
					},
				},
				LocalIdentity: &s2apb.Identity{
					IdentityOneof: &s2apb.Identity_SpiffeId{
						SpiffeId: "peer spiffe identity",
					},
				},
				PeerCertFingerprint:  []byte("peer cert fingerprint"),
				LocalCertFingerprint: []byte("local cert fingerprint"),
			},
			outAppProtocol: "app protocol",
			outTLSVersion:  s2apb.TLSVersion_TLS1_2,
			outCiphersuite: s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			outPeerIdentity: &s2apb.Identity{
				IdentityOneof: &s2apb.Identity_Hostname{
					Hostname: "local hostname",
				},
			},
			outLocalIdentity: &s2apb.Identity{
				IdentityOneof: &s2apb.Identity_SpiffeId{
					SpiffeId: "peer spiffe identity",
				},
			},
			outPeerCertFingerprint:  []byte("peer cert fingerprint"),
			outLocalCertFingerprint: []byte("local cert fingerprint"),
		},
		{
			desc: "nil identities and fingerprints",
			sessionResult: &s2apb.SessionResult{
				ApplicationProtocol: "app protocol",
				State: &s2apb.SessionState{
					TlsVersion:     s2apb.TLSVersion_TLS1_3,
					TlsCiphersuite: s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
				},
			},
			outAppProtocol: "app protocol",
			outTLSVersion:  s2apb.TLSVersion_TLS1_3,
			outCiphersuite: s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
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
