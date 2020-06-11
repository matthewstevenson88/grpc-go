package crypter

import (
	"crypto/sha256"
	"crypto/sha512"
	"google.golang.org/grpc/security/s2a/internal/crypter/testutil"
	s2a_proto "google.golang.org/grpc/security/s2a/internal/proto"
	"hash"
	"reflect"
	"testing"
)

func TestCiphersuites(t *testing.T) {
	for _, tc := range []struct {
		s2aProtoCiphersuite                   s2a_proto.Ciphersuite
		expectedCiphersuite                   ciphersuite
		dummyKey                              []byte
		keySize, nonceSize, trafficSecretSize int
		hashFunction                          func() hash.Hash
		aeadCrypter                           s2aAeadCrypter
	}{
		{
			s2aProtoCiphersuite: s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
			expectedCiphersuite: &aesgcm128sha256{},
			dummyKey:            testutil.Dehex("88ee087fd95da9fbf6725aa9d757b0cd"),
			keySize:             aes128GcmKeySize,
			nonceSize:           nonceSize,
			trafficSecretSize:   sha256DigestSize,
			hashFunction:        sha256.New,
			aeadCrypter:         &aesgcm{},
		},
		{
			s2aProtoCiphersuite: s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
			expectedCiphersuite: &aesgcm256sha384{},
			dummyKey:            testutil.Dehex("83c093b58de7ffe1c0da926ac43fb3609ac1c80fee1b624497ef942e2f79a823"),
			keySize:             aes256GcmKeySize,
			nonceSize:           nonceSize,
			trafficSecretSize:   sha384DigestSize,
			hashFunction:        sha512.New384,
			aeadCrypter:         &aesgcm{},
		},
		{
			s2aProtoCiphersuite: s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
			expectedCiphersuite: &chachapolysha256{},
			dummyKey:            testutil.Dehex("83c093b58de7ffe1c0da926ac43fb3609ac1c80fee1b624497ef942e2f79a823"),
			keySize:             chacha20Poly1305KeySize,
			nonceSize:           nonceSize,
			trafficSecretSize:   sha256DigestSize,
			hashFunction:        sha256.New,
			aeadCrypter:         &chachapoly{},
		},
	} {
		t.Run(tc.s2aProtoCiphersuite.String(), func(t *testing.T) {
			hc := newCiphersuite(tc.s2aProtoCiphersuite)
			if got, want := hc, tc.expectedCiphersuite; got != want {
				t.Fatalf("newCiphersuite(%v) = %v, want %v", tc.s2aProtoCiphersuite, got, want)
			}
			if got, want := hc.keySize(), tc.keySize; got != want {
				t.Errorf("keySize = %v, want %v", got, want)
			}
			if got, want := hc.nonceSize(), tc.nonceSize; got != want {
				t.Errorf("nonceSize = %v, want %v", got, want)
			}
			if got, want := hc.trafficSecretSize(), tc.trafficSecretSize; got != want {
				t.Errorf("trafficSecretSize = %v, want %v", got, want)
			}
			if got, want := reflect.TypeOf(hc.hashFunction()), reflect.TypeOf(tc.hashFunction); got != want {
				t.Errorf("hashFunction = %v, want %v", got, want)
			}
			aeadCrypter, err := hc.aeadCrypter(tc.dummyKey)
			if err != nil {
				t.Fatalf("hc.aeadCrypter(%v) failed with error: %v", tc.dummyKey, err)
			}
			if got, want := reflect.TypeOf(aeadCrypter), reflect.TypeOf(tc.aeadCrypter); got != want {
				t.Errorf("hashFunction = %v, want %v", got, want)
			}
		})
	}
}
