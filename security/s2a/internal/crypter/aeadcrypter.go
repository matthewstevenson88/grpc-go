package crypter

// s2aAeadCrypter is the interface for an AEAD cipher used by the S2A record
// protocol.
type s2aAeadCrypter interface {
	// encrypt encrypts the plaintext and computes the tag of dst and plaintext.
	// dst and plaintext may fully overlap or not at all.
	encrypt(dst, plaintext, nonce, aad []byte) ([]byte, error)
	// decrypt decrypts ciphertext and verifies the tag. dst and ciphertext may
	// fully overlap or not at all.
	decrypt(dst, ciphertext, nonce, aad []byte) ([]byte, error)
	// tagSize returns the tag size in bytes.
	tagSize() int
}
