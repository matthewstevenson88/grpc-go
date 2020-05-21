package crypter

// S2AAeadCrypter is the interface for gRPC S2A record protocol.
type S2AAeadCrypter interface {
	// Encrypt encrypts the plaintext and computes the tag (if any) of dst
	// and plaintext, dst and plaintext do not overlap.
	Encrypt(dst, plaintext []byte) ([]byte, error)
	// Decrypt decrypts ciphertext and verifies the tag (if any). dst and
	// ciphertext may alias exactly or not at all. To reuse ciphertext's
	// storage for the decrypted output, use ciphertext[:0] as dst.
	Decrypt(dst, ciphertext []byte) ([]byte, error)
	// TagSize returns the tag size (if any) in bytes.
	TagSize() int
	// UpdateKey updates the key used for encryption and decryption.
	UpdateKey(key []byte) error
}
