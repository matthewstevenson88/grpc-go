package crypter

// S2AAeadCrypter is the interface for an AEAD cipher used by the S2A record protocol.
type S2AAeadCrypter interface {
	// Encrypt encrypts the plaintext and computes the tag of dst
	// and plaintext. dst and plaintext do not overlap.
	Encrypt(dst, plaintext []byte) ([]byte, error)
	// Decrypt decrypts ciphertext and verifies the tag. dst and
	// ciphertext may alias exactly or not at all.
	Decrypt(dst, ciphertext []byte) ([]byte, error)
	// TagSize returns the tag size in bytes.
	TagSize() int
	// UpdateKey updates the key used for encryption and decryption.
	UpdateKey(key []byte) error
}
