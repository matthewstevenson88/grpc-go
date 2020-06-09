package crypter

import (
	"crypto/sha256"
	"golang.org/x/crypto/sha3"
	s2a_proto "google.golang.org/grpc/security/s2a/internal"
	"hash"
)

type ciphersuite interface {
	// keySize returns the key size in bytes.
	keySize() int
	// nonceSize returns the nonce size in bytes.
	nonceSize() int
	// trafficSecretSize returns the traffic secret size in bytes.
	trafficSecretSize() int
	// hashFunction returns the hash function for the ciphersuite.
	hashFunction() func() hash.Hash
	// aeadCrypter returns the AEAD crypter for the ciphersuite.
	aeadCrypter(key []byte) (s2aAeadCrypter, error)
}

func NewCiphersuite(ciphersuite s2a_proto.Ciphersuite) ciphersuite {
	switch ciphersuite {
	case s2a_proto.Ciphersuite_AES_128_GCM_SHA256:
		return &aesgcm128sha256{}
	case s2a_proto.Ciphersuite_AES_256_GCM_SHA384:
		return &aesgcm256sha384{}
	case s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256:
		return &chachapolysha256{}
	default:
		panic("unrecognized ciphersuite")
	}
}

type aesgcm128sha256 struct{}

func (aesgcm128sha256) keySize() int {
	return aes128GcmKeySize
}

func (aesgcm128sha256) nonceSize() int {
	return nonceSize
}

func (aesgcm128sha256) trafficSecretSize() int {
	return sha256DigestLength
}

func (aesgcm128sha256) hashFunction() func() hash.Hash {
	return sha256.New
}

func (aesgcm128sha256) aeadCrypter(key []byte) (s2aAeadCrypter, error) {
	return newAESGCM(key)
}

type aesgcm256sha384 struct{}

func (aesgcm256sha384) keySize() int {
	return aes256GcmKeySize
}

func (aesgcm256sha384) nonceSize() int {
	return nonceSize
}

func (aesgcm256sha384) trafficSecretSize() int {
	return sha384DigestLength
}

func (aesgcm256sha384) hashFunction() func() hash.Hash {
	return sha3.New384
}

func (aesgcm256sha384) aeadCrypter(key []byte) (s2aAeadCrypter, error) {
	return newAESGCM(key)
}

// TODO(rnkim): Implement this once #15 is merged.
type chachapolysha256 struct{}

func (chachapolysha256) keySize() int {
	panic("keySize unimplemented")
}

func (chachapolysha256) nonceSize() int {
	panic("nonceSize unimplemented")
}

func (chachapolysha256) trafficSecretSize() int {
	panic("expectedTrafficSecretSize unimplemented")
}

func (chachapolysha256) hashFunction() func() hash.Hash {
	panic("hashFunction unimplemented")
}

func (chachapolysha256) aeadCrypter(key []byte) (s2aAeadCrypter, error) {
	panic("aeadCrypter unimplemented")
}
