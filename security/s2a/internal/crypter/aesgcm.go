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
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// Supported key sizes in bytes.
const (
	AesGcmKeySize128 = 16
	AesGcmKeySize256 = 32
)

// aesgcm is the struct that holds necessary information for S2A record.
type aesgcm struct {
	aead cipher.AEAD
}

// NewAESGCM creates an instance that uses aesgcm for S2A record. Note that the
// key must be either 128 bits or 256 bits.
func NewAESGCM(key []byte) (S2AAeadCrypter, error) {
	crypter := aesgcm{}
	err := crypter.UpdateKey(key)
	if err != nil {
		return nil, err
	}
	return &crypter, err
}

// Encrypt is the encryption function. dst can contain bytes at the beginning of
// the ciphertext that will not be encrypted but will be authenticated. If dst
// has enough capacity to hold these bytes, the ciphertext and the tag, no
// allocation and copy operations will be performed. dst and plaintext may
// fully overlap or not at all.
func (s *aesgcm) Encrypt(dst, plaintext, nonce, aad []byte) ([]byte, error) {
	// If we need to allocate an output buffer, we want to include space for
	// GCM tag to avoid forcing S2A record to reallocate as well.
	dlen := len(dst)
	dst, out := SliceForAppend(dst, len(plaintext)+GcmTagSize)
	data := out[:len(plaintext)]
	copy(data, plaintext) // data may fully overlap plaintext

	// Seal appends the ciphertext and the tag to its first argument and
	// returns the updated slice. However, SliceForAppend above ensures that
	// dst has enough capacity to avoid a reallocation and copy due to the
	// append.
	dst = s.aead.Seal(dst[:dlen], nonce, data, aad)
	return dst, nil
}

func (s *aesgcm) Decrypt(dst, ciphertext, nonce, aad []byte) ([]byte, error) {
	// If dst is equal to ciphertext[:0], ciphertext storage is reused.
	plaintext, err := s.aead.Open(dst, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAuth
	}
	return plaintext, nil
}

func (s *aesgcm) TagSize() int {
	return GcmTagSize
}

func (s *aesgcm) UpdateKey(key []byte) error {
	if len(key) != AesGcmKeySize128 && len(key) != AesGcmKeySize256 {
		return fmt.Errorf("supplied key must be 128 or 256 bits. given: %d", len(key)*8)
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	a, err := cipher.NewGCM(c)
	if err != nil {
		return err
	}
	s.aead = a
	return nil
}