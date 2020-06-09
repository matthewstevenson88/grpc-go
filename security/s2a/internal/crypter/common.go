package crypter

const (
	// gcmTagSize is the tag size in bytes. From crypto/cipher/gcm.go in the Go
	// crypto library.
	gcmTagSize = 16
	// nonceSize is the size of the nonce in number of bytes for
	// AES-128-GCM-SHA256, AES-256-GCM-SHA384, and CHACHA20-POLY1305-SHA256.
	nonceSize = 12
	// sha256DigestLength is the digest length of sha256 in bytes.
	sha256DigestLength = 32
	// sha384DigestLength is the digest length of sha384 in bytes.
	sha384DigestLength = 48
	// uint64Size is the size of a uint64 in bytes.
	uint64Size = 8
)

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return head, tail
}
