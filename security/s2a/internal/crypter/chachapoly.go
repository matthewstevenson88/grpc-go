/*
 *
 * Copyright 2020 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package crypter

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Supported key sizes in bytes.
const (
	chacha20Poly1305KeySize = 32
)

// chachapoly is the struct that holds a CHACHA-POLY cipher for the S2A AEAD crypter.
type chachapoly struct {
	aead cipher.AEAD
	// keySize stores the size of the key which was initially used. This
	// is necessary to restrict key updates to the same key length as the
	// initial key.
	keySize int
}

// newChachaPoly creates a Chacha-Poly crypter instance. Note that the key must be
// 32 bytes.
func newChachaPoly(key []byte) (s2aAeadCrypter, error) {
	if len(key) != chacha20Poly1305KeySize {
		return nil, fmt.Errorf("32 bytes, given: %d", len(key))
	}
	crypter := chachapoly{keySize: len(key)}
	err := crypter.updateKey(key)
	if err != nil {
		return nil, err
	}
	return &crypter, err
}

// encrypt is the encryption function. dst can contain bytes at the beginning of
// the ciphertext that will not be encrypted but will be authenticated. If dst
// has enough capacity to hold these bytes, the ciphertext and the tag, no
// allocation and copy operations will be performed. dst and plaintext may
// fully overlap or not at all.
func (s *chachapoly) encrypt(dst, plaintext, nonce, aad []byte) ([]byte, error) {
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("nonce size must be %d bytes. received: %d", nonceSize, len(nonce))
	}
	// If we need to allocate an output buffer, we want to include space for
	// the tag to avoid forcing TLS record to reallocate as well.
	dlen := len(dst)
	dst, out := sliceForAppend(dst, len(plaintext)+tagSize)
	data := out[:len(plaintext)]
	copy(data, plaintext) // data may fully overlap plaintext

	// Seal appends the ciphertext and the tag to its first argument and
	// returns the updated slice. However, sliceForAppend above ensures that
	// dst has enough capacity to avoid a reallocation and copy due to the
	// append.
	dst = s.aead.Seal(dst[:dlen], nonce, data, aad)
	return dst, nil
}

func (s *chachapoly) decrypt(dst, ciphertext, nonce, aad []byte) ([]byte, error) {
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("nonce size must be %d bytes. received: %d", nonceSize, len(nonce))
	}
	// If dst is equal to ciphertext[:0], ciphertext storage is reused.
	plaintext, err := s.aead.Open(dst, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("message auth failed: %v", err)
	}
	return plaintext, nil
}

func (s *chachapoly) tagSize() int {
	return tagSize
}

func (s *chachapoly) updateKey(key []byte) error {
	if s.keySize != len(key) {
		return fmt.Errorf("supplied key must have same size as initial key: %d bytes", s.keySize)
	}
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	s.aead = c
	return nil
}
