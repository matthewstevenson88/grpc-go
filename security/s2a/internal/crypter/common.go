package crypter

import (
	"crypto/cipher"
	"fmt"
)

const (
	// tagSize is the tag size in bytes for AES-128-GCM-SHA256,
	// AES-256-GCM-SHA384, and CHACHA20-POLY1305-SHA256.
	tagSize = 16
	// nonceSize is the size of the nonce in number of bytes for
	// AES-128-GCM-SHA256, AES-256-GCM-SHA384, and CHACHA20-POLY1305-SHA256.
	nonceSize = 12
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

// encrypt is the encryption function for an AEAD crypter. aead determines
// the type of AEAD crypter. dst can contain bytes at the beginning of
// the ciphertext that will not be encrypted but will be authenticated. If dst
// has enough capacity to hold these bytes, the ciphertext and the tag, no
// allocation and copy operations will be performed. dst and plaintext may
// fully overlap or not at all.
func encrypt(aead cipher.AEAD, dst, plaintext, nonce, aad []byte) ([]byte, error) {
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("nonce size must be %d bytes. received: %d", nonceSize, len(nonce))
	}
	// If we need to allocate an output buffer, we want to include space for
	// the tag to avoid forcing the caller to reallocate as well.
	dlen := len(dst)
	dst, out := sliceForAppend(dst, len(plaintext)+tagSize)
	data := out[:len(plaintext)]
	copy(data, plaintext) // data may fully overlap plaintext

	// Seal appends the ciphertext and the tag to its first argument and
	// returns the updated slice. However, sliceForAppend above ensures that
	// dst has enough capacity to avoid a reallocation and copy due to the
	// append.
	dst = aead.Seal(dst[:dlen], nonce, data, aad)
	return dst, nil
}

// decrypt is the decryption function for an AEAD crypter, where aead determines
// the type of AEAD crypter, and dst the destination bytes for the decrypted
// ciphertext. The dst buffer may fully overlap with plaintext or not at all.
func decrypt(aead cipher.AEAD, dst, ciphertext, nonce, aad []byte) ([]byte, error) {
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("nonce size must be %d bytes. received: %d", nonceSize, len(nonce))
	}
	// If dst is equal to ciphertext[:0], ciphertext storage is reused.
	plaintext, err := aead.Open(dst, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("message auth failed: %v", err)
	}
	return plaintext, nil
}
