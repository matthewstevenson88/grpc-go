package crypter

// S2AAeadCrypter is the interface for an AEAD cipher used by the S2A record
// protocol.
type S2AAeadCrypter interface {
	// Encrypt encrypts plaintext, computes the tag of plaintext, and appends
	// the resulting ciphertext to dst, returning the updated slice. dst and
	// plaintext may fully overlap or not at all.
	Encrypt(dst, plaintext []byte) ([]byte, error)
	// Decrypt decrypts ciphertext, verifies the tag, and appends the resulting
	// plaintext to dst, returning the updated slice. dst and ciphertext may
	// fully overlap or not at all.
	Decrypt(dst, ciphertext []byte) ([]byte, error)
	// TagSize returns the tag size in bytes.
	TagSize() int
	// UpdateKey updates the key used for encryption and decryption.
	UpdateKey(key []byte) error
}
