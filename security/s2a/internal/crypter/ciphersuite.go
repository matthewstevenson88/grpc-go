package crypter

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	s2a_proto "google.golang.org/grpc/security/s2a/internal/proto"
	"hash"
)

// ciphersuite is the interface for retrieving ciphersuite-specific information
// and utilities.
type ciphersuite interface {
	// keySize returns the key size in bytes. This refers to the key used by
	// the AEAD crypter. This is derived by calling HKDF expand on the traffic
	// secret.
	keySize() int
	// nonceSize returns the nonce size in bytes.
	nonceSize() int
	// trafficSecretSize returns the traffic secret size in bytes. This refers
	// to the secret used to derive the traffic key and nonce, as specified in
	// https://tools.ietf.org/html/rfc8446#section-7.
	trafficSecretSize() int
	// hashFunction returns the hash function for the ciphersuite.
	hashFunction() func() hash.Hash
	// aeadCrypter takes a key and creates an AEAD crypter for the ciphersuite
	// using that key.
	aeadCrypter(key []byte) (s2aAeadCrypter, error)
}

func newCiphersuite(ciphersuite s2a_proto.Ciphersuite) (ciphersuite, error) {
	switch ciphersuite {
	case s2a_proto.Ciphersuite_AES_128_GCM_SHA256:
		return &aesgcm128sha256{}, nil
	case s2a_proto.Ciphersuite_AES_256_GCM_SHA384:
		return &aesgcm256sha384{}, nil
	case s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256:
		return &chachapolysha256{}, nil
	default:
		return nil, fmt.Errorf("unrecognized ciphersuite: %v", ciphersuite)
	}
}

// aesgcm128sha256 is the AES-128-GCM-SHA256 implementation of the ciphersuite
// interface.
type aesgcm128sha256 struct{}

func (aesgcm128sha256) keySize() int                                   { return aes128GcmKeySize }
func (aesgcm128sha256) nonceSize() int                                 { return nonceSize }
func (aesgcm128sha256) trafficSecretSize() int                         { return sha256DigestSize }
func (aesgcm128sha256) hashFunction() func() hash.Hash                 { return sha256.New }
func (aesgcm128sha256) aeadCrypter(key []byte) (s2aAeadCrypter, error) { return newAESGCM(key) }

// aesgcm256sha384 is the AES-256-GCM-SHA384 implementation of the ciphersuite
// interface.
type aesgcm256sha384 struct{}

func (aesgcm256sha384) keySize() int                                   { return aes256GcmKeySize }
func (aesgcm256sha384) nonceSize() int                                 { return nonceSize }
func (aesgcm256sha384) trafficSecretSize() int                         { return sha384DigestSize }
func (aesgcm256sha384) hashFunction() func() hash.Hash                 { return sha512.New384 }
func (aesgcm256sha384) aeadCrypter(key []byte) (s2aAeadCrypter, error) { return newAESGCM(key) }

// chachapolysha256 is the ChaChaPoly-SHA256 implementation of the ciphersuite
// interface.
type chachapolysha256 struct{}

func (chachapolysha256) keySize() int                                   { return chacha20Poly1305KeySize }
func (chachapolysha256) nonceSize() int                                 { return nonceSize }
func (chachapolysha256) trafficSecretSize() int                         { return sha256DigestSize }
func (chachapolysha256) hashFunction() func() hash.Hash                 { return sha256.New }
func (chachapolysha256) aeadCrypter(key []byte) (s2aAeadCrypter, error) { return newChachaPoly(key) }
