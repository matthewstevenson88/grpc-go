package aeadcrypter

// S2AAEADCrypter is the interface for an AEAD cipher used by the S2A record
// protocol.
type S2AAEADCrypter interface {
	// Encrypt encrypts the plaintext and computes the tag of dst and plaintext.
	// dst and plaintext may fully overlap or not at all.
	Encrypt(dst, plaintext, nonce, aad []byte) ([]byte, error)
	// Decrypt decrypts ciphertext and verifies the tag. dst and ciphertext may
	// fully overlap or not at all.
	Decrypt(dst, ciphertext, nonce, aad []byte) ([]byte, error)
	// TagSize returns the tag size in bytes.
	TagSize() int
}
