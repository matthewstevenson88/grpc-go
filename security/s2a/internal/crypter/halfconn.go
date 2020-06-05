package crypter

import (
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"hash"
)

type S2AHalfConnection struct {
	aeadCrypter s2aAeadCrypter
	expander    hkdfExpander
	sequence    counter
}

func NewHalfConn(aeadCrypter s2aAeadCrypter, expander hkdfExpander) S2AHalfConnection {
	return S2AHalfConnection{aeadCrypter, expander, newCounter()}
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

// expandLabel implements HKDF-Expand-Label specified in
// https://tools.ietf.org/html/rfc8446#section-7.1. Note that the `Context` and
// `Length` parameters have been omitted since we always pass in an empty string
// for `Context` and we used a fixed length.
func (hc *S2AHalfConnection) expandLabel(h func() hash.Hash, secret, label []byte) ([]byte, error) {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(h().Size()))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(append([]byte("tls13 "), label...))
	})
	hkdfLabelBytes, err := hkdfLabel.Bytes()
	if err != nil {
		return nil, fmt.Errorf("hkdfExpandLabel failed with error: %v", err)
	}
	return hc.expander.expand(h, secret, hkdfLabelBytes)
}
