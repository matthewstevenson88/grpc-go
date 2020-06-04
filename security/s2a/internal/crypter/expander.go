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
	// expand takes a hashing function, a secret, a label, and an output length
	// in number of bytes, and returns the resulting expanded key.
	expand(hash func() hash.Hash, secret, label []byte, length int) ([]byte, error)
}

// defaultHKDFExpander is the default HKDF expander which uses Go's crypto/hkdf
// for HKDF expansion.
type defaultHKDFExpander struct{}

// newDefaultHKDFExpander creates an instance of the default HKDF expander.
func newDefaultHKDFExpander() hkdfExpander {
	return &defaultHKDFExpander{}
}

func (*defaultHKDFExpander) expand(hash func() hash.Hash, secret, label []byte, length int) ([]byte, error) {
	outBuf := make([]byte, length)
	n, err := hkdf.Expand(hash, secret, label).Read(outBuf)
	if err != nil {
		return nil, fmt.Errorf("hkdf.expand.Read failed with error: %v", err)
	}
	if n != length {
		return nil, fmt.Errorf("hkdf.expand.Read returned unexpected length, got: %d, want: %d", n, length)
	}
	return outBuf, nil
}
