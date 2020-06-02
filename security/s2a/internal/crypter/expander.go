package crypter

import "hash"

// HKDFExpander is the interface for the HKDF expansion function; see
// https://tools.ietf.org/html/rfc5869 for details. It's use in TLS 1.3 is specified in
// https://tools.ietf.org/html/rfc8446#section-7.2
type HKDFExpander interface {
	Expand(hash func() hash.Hash, secret, label []byte, length int) ([]byte, error)
}
