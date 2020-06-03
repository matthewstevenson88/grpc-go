package crypter

import (
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
