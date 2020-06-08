package crypter

import (
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/sha3"
	s2a_proto "google.golang.org/grpc/security/s2a/internal"
	"hash"
)

type S2AHalfConnection struct {
	aeadCrypter   s2aAeadCrypter
	expander      hkdfExpander
	seqCounter    counter
	trafficSecret []byte
	nonce         []byte
}

func NewHalfConn(ciphersuite s2a_proto.Ciphersuite, trafficSecret []byte) (S2AHalfConnection, error) {
	var h func() hash.Hash
	switch ciphersuite {
	case s2a_proto.Ciphersuite_AES_128_GCM_SHA256:
		h = sha256.New
	case s2a_proto.Ciphersuite_AES_256_GCM_SHA384:
		h = sha3.New384
	case s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256:
		h = sha256.New
	}

	hc := S2AHalfConnection{expander: &defaultHKDFExpander{}, seqCounter: newCounter()}
	key, err := hc.deriveSecret(h, trafficSecret, []byte("tls13 key"))
	if err != nil {
		return S2AHalfConnection{}, fmt.Errorf("hc.deriveSecret(h, %v, \"tls13 key\") failed with error: %v", trafficSecret, err)
	}
	hc.nonce, err = hc.deriveSecret(h, trafficSecret, []byte("tls13 iv"))
	if err != nil {
		return S2AHalfConnection{}, fmt.Errorf("hc.deriveSecret(h, %v, \"tls13 iv\") failed with error: %v", trafficSecret, err)
	}

	switch ciphersuite {
	case s2a_proto.Ciphersuite_AES_128_GCM_SHA256, s2a_proto.Ciphersuite_AES_256_GCM_SHA384:
		crypter, err := newAESGCM(key)
		if err != nil {
			return S2AHalfConnection{}, fmt.Errorf("newAESGCM(%v) failed with error: %v", key, err)
		}
		hc.aeadCrypter = crypter
	case s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256:
		// TODO(rnkim): Implement this.
		panic("unimplemented")
	}

	return hc, nil
}

func (hc *S2AHalfConnection) Encrypt(dst, plaintext, aad []byte) ([]byte, error) {
	// TODO(rnkim): Implement this.
	panic("Encrypt currently unimplemented")
}

func (hc *S2AHalfConnection) Decrypt(dst, ciphertext, aad []byte) ([]byte, error) {
	// TODO(rnkim): Implement this.
	panic("Decrypt currently unimplemented")
}

func (hc *S2AHalfConnection) UpdateKey(key []byte) error {
	// TODO(rnkim): Implement this.
	panic("UpdateKey currently unimplemented")
}

// deriveSecret implements Derive-Secret specified in
// https://tools.ietf.org/html/rfc8446#section-7.1. Note that the `Context` and
// `Length` parameters have been omitted since we always pass in an empty string
// for `Context` and we use a fixed length for `Length`.
func (hc *S2AHalfConnection) deriveSecret(h func() hash.Hash, secret, label []byte) ([]byte, error) {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(h().Size()))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(label)
	})
	hkdfLabelBytes, err := hkdfLabel.Bytes()
	if err != nil {
		return nil, fmt.Errorf("deriveSecret failed with error: %v", err)
	}
	return hc.expander.expand(h, secret, hkdfLabelBytes)
}
