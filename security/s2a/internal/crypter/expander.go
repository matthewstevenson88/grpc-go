package crypter

import (
	"fmt"
	"golang.org/x/crypto/hkdf"
	"hash"
)

// hkdfExpander is the interface for the HKDF expansion function; see
// https://tools.ietf.org/html/rfc5869 for details. It's use in TLS 1.3 is
// specified in https://tools.ietf.org/html/rfc8446#section-7.2
type hkdfExpander interface {
	// expand takes a hashing function, a secret, a label, and returns the
	// resulting expanded key.
	expand(h func() hash.Hash, secret, label []byte) ([]byte, error)
}

// defaultHKDFExpander is the default HKDF expander which uses Go's crypto/hkdf
// for HKDF expansion.
type defaultHKDFExpander struct{}

// newDefaultHKDFExpander creates an instance of the default HKDF expander.
func newDefaultHKDFExpander() hkdfExpander {
	return &defaultHKDFExpander{}
}

func (*defaultHKDFExpander) expand(h func() hash.Hash, secret, label []byte) ([]byte, error) {
	length := h().Size()
	outBuf := make([]byte, length)
	n, err := hkdf.Expand(h, secret, label).Read(outBuf)
	if err != nil {
		return nil, fmt.Errorf("hkdf.Expand.Read failed with error: %v", err)
	}
	if n < length {
		return nil, fmt.Errorf("hkdf.Expand.Read returned unexpected length, got %d, want %d", n, length)
	}
	return outBuf, nil
}
