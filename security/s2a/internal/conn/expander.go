package conn

import "hash"

// HKDFExpander is the interface for an HMAC-based Extract-and-Expand Key
// Derivation Function (HKDF) expander. This is specified in Section 7 of
// https://tools.ietf.org/html/rfc8446
type HKDFExpander interface {
	ExpandLabel(hash func() hash.Hash, secret, label []byte, length int) ([]byte, error)
}
