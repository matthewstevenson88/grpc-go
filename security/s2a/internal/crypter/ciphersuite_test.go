package crypter

import (
	s2a_proto "google.golang.org/grpc/security/s2a/internal/proto"
	"testing"
)

func TestCiphersuites(t *testing.T) {
	for _, tc := range []struct {
		s2aProtoCiphersuite s2a_proto.Ciphersuite
		expectedCiphersuite ciphersuite
	}{
		{
			s2aProtoCiphersuite: s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
			expectedCiphersuite: &aesgcm128sha256{},
		},
		{
			s2aProtoCiphersuite: s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
			expectedCiphersuite: &aesgcm256sha384{},
		},
		{
			s2aProtoCiphersuite: s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
			expectedCiphersuite: &chachapolysha256{},
		},
	} {
		t.Run(tc.s2aProtoCiphersuite.String(), func(t *testing.T) {
			if got, want := newCiphersuite(tc.s2aProtoCiphersuite), tc.expectedCiphersuite; got != want {
				t.Fatalf("newCiphersuite(%v) = %v, want %v", tc.s2aProtoCiphersuite, got, want)
			}
		})
	}
}
