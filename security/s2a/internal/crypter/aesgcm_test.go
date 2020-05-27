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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// Constants indicating whether the test vector is valid or not.
const (
	validResult   = "valid"
	invalidResult = "invalid"
)

// cryptoTestVector is a struct for a AES-GCM test vector
type cryptoTestVector struct {
	id                                          int
	key, plaintext, ciphertext, tag, nonce, aad []byte
	result, comment                             string
	allocateDst                                 bool
}

// testVector is a struct for a WycheProof test vector
type testVector struct {
	TcId    int    `json:"tcId"`
	Comment string `json:"comment"`
	Key     string `json:"key"`
	Iv      string `json:"iv"`
	Aad     string `json:"aad"`
	Msg     string `json:"msg"`
	Ct      string `json:"ct"`
	Tag     string `json:"tag"`
	Result  string `json:"result"`
}

// testGroup is a struct for a WycheProof test group
type testGroup struct {
	IvSize  int          `json:"ivSize"`
	KeySize int          `json:"keySize"`
	TagSize int          `json:"tagSize"`
	Tests   []testVector `json:"tests"`
}

// testFile is a struct for a WycheProof test file
type testFile struct {
	TestGroups []testGroup `json:"testGroups"`
}

// getGCMCryptoPair outputs a client/server pair on AES-GCM.
func getGCMCryptoPair(key []byte, t *testing.T) (S2AAeadCrypter, S2AAeadCrypter) {
	client, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("NewAESGCM(ClientSide, key) = %v", err)
	}
	server, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("NewAESGCM(ServerSide, key) = %v", err)
	}
	return client, server
}

func parseWycheProofTestVectors(jsonFilePath string, t *testing.T) []cryptoTestVector {
	jsonFile, err := os.Open(jsonFilePath)
	if err != nil {
		t.Fatalf("failed to open wycheproof json test vectors file: %v", err)
	}
	defer jsonFile.Close()

	dec := json.NewDecoder(jsonFile)

	var tf testFile
	err = dec.Decode(&tf)
	if err != nil {
		t.Fatalf("failed to decode wycheproof json file: %v", err)
	}

	var testVectors []cryptoTestVector
	for _, testGroup := range tf.TestGroups {
		// Skip over unsupported inputs.
		if isUnsupportedInput(testGroup.IvSize, testGroup.KeySize, testGroup.TagSize) {
			continue
		}
		for _, test := range testGroup.Tests {
			testVectors = append(testVectors, cryptoTestVector{
				key:         dehex(test.Key),
				plaintext:   dehex(test.Msg),
				ciphertext:  dehex(test.Ct),
				tag:         dehex(test.Tag),
				nonce:       dehex(test.Iv),
				aad:         dehex(test.Aad),
				result:      test.Result,
				comment:     test.Comment,
				id:          test.TcId,
				allocateDst: true,
			})
		}
	}

	return testVectors
}

func isFailure(result string, err error, got, expected []byte) bool {
	return (result == validResult && (err != nil || !bytes.Equal(got, expected))) ||
		(result == invalidResult && bytes.Equal(got, expected))
}

func isUnsupportedInput(ivSize, keySize, tagSize int) bool {
	return ivSize != 96 || (keySize != 128 && keySize != 256) || tagSize != 128
}

func TestWycheProofTestVectors(t *testing.T) {
	for _, test := range parseWycheProofTestVectors("testdata/aes_gcm_wycheproof.json", t) {
		t.Run(fmt.Sprintf("%d/%s", test.id, test.comment), func(t *testing.T) {
			// Test encryption and decryption for AES-GCM.
			client, server := getGCMCryptoPair(test.key, t)
			testGCMEncryptionDecryption(client, server, &test, t)
		})
	}
}

func testGCMEncryptionDecryption(sender S2AAeadCrypter, receiver S2AAeadCrypter, test *cryptoTestVector, t *testing.T) {
	// Ciphertext is: encrypted text + tag.
	var ciphertext []byte
	ciphertext = append(ciphertext, test.ciphertext...)
	ciphertext = append(ciphertext, test.tag...)

	// Decrypt.
	got, err := receiver.Decrypt(nil, ciphertext, test.nonce, test.aad)
	if isFailure(test.result, err, got, test.plaintext) {
		t.Errorf("key=%v\ntag=%v\nciphertext=%v\nDecrypt = %v, %v\nwant: %v",
			test.key, test.tag, ciphertext, got, err, test.plaintext)
	}

	// Encrypt.
	var dst []byte
	if test.allocateDst {
		dst = make([]byte, len(test.plaintext)+sender.TagSize())
	}
	got, err = sender.Encrypt(dst[:0], test.plaintext, test.nonce, test.aad)
	if isFailure(test.result, err, got, ciphertext) {
		t.Errorf("key=%v\nplaintext=%v\nEncrypt = %v, %v\nwant: %v",
			test.key, test.plaintext, got, err, ciphertext)
	}
}

// Test encrypt and decrypt using test vectors for aes128gcm.
func TestAESGCMEncrypt(t *testing.T) {
	for _, test := range []cryptoTestVector{
		{
			key:         dehex("5b9604fe14eadba931b0ccf34843dab9"),
			plaintext:   dehex("001d0c231287c1182784554ca3a21908"),
			ciphertext:  dehex("26073cc1d851beff176384dc9896d5ff"),
			tag:         dehex("0a3ea7a5487cb5f7d70fb6c58d038554"),
			nonce:       dehex("028318abc1824029138141a2"),
			result:      validResult,
			allocateDst: true,
		},
		{
			key:         dehex("11754cd72aec309bf52f7687212e8957"),
			plaintext:   nil,
			ciphertext:  nil,
			tag:         dehex("250327c674aaf477aef2675748cf6971"),
			nonce:       dehex("3c819d9a9bed087615030b65"),
			result:      validResult,
			allocateDst: false,
		},
		{
			key:         dehex("ca47248ac0b6f8372a97ac43508308ed"),
			plaintext:   nil,
			ciphertext:  nil,
			tag:         dehex("60d20404af527d248d893ae495707d1a"),
			nonce:       dehex("ffd2b598feabc9019262d2be"),
			result:      validResult,
			allocateDst: false,
		},
		{
			key:         dehex("7fddb57453c241d03efbed3ac44e371c"),
			plaintext:   dehex("d5de42b461646c255c87bd2962d3b9a2"),
			ciphertext:  dehex("2ccda4a5415cb91e135c2a0f78c9b2fd"),
			tag:         dehex("b36d1df9b9d5e596f83e8b7f52971cb3"),
			nonce:       dehex("ee283a3fc75575e33efd4887"),
			result:      validResult,
			allocateDst: false,
		},
		{
			key:         dehex("ab72c77b97cb5fe9a382d9fe81ffdbed"),
			plaintext:   dehex("007c5e5b3e59df24a7c355584fc1518d"),
			ciphertext:  dehex("0e1bde206a07a9c2c1b65300f8c64997"),
			tag:         dehex("2b4401346697138c7a4891ee59867d0c"),
			nonce:       dehex("54cc7dc2c37ec006bcc6d1da"),
			result:      validResult,
			allocateDst: false,
		},
		{
			key:         dehex("11754cd72aec309bf52f7687212e8957"),
			plaintext:   nil,
			ciphertext:  nil,
			tag:         dehex("250327c674aaf477aef2675748cf6971"),
			nonce:       dehex("3c819d9a9bed087615030b65"),
			result:      validResult,
			allocateDst: true,
		},
		{
			key:         dehex("ca47248ac0b6f8372a97ac43508308ed"),
			plaintext:   nil,
			ciphertext:  nil,
			tag:         dehex("60d20404af527d248d893ae495707d1a"),
			nonce:       dehex("ffd2b598feabc9019262d2be"),
			result:      validResult,
			allocateDst: true,
		},
		{
			key:         dehex("7fddb57453c241d03efbed3ac44e371c"),
			plaintext:   dehex("d5de42b461646c255c87bd2962d3b9a2"),
			ciphertext:  dehex("2ccda4a5415cb91e135c2a0f78c9b2fd"),
			tag:         dehex("b36d1df9b9d5e596f83e8b7f52971cb3"),
			nonce:       dehex("ee283a3fc75575e33efd4887"),
			result:      validResult,
			allocateDst: true,
		},
		{
			key:         dehex("ab72c77b97cb5fe9a382d9fe81ffdbed"),
			plaintext:   dehex("007c5e5b3e59df24a7c355584fc1518d"),
			ciphertext:  dehex("0e1bde206a07a9c2c1b65300f8c64997"),
			tag:         dehex("2b4401346697138c7a4891ee59867d0c"),
			nonce:       dehex("54cc7dc2c37ec006bcc6d1da"),
			result:      validResult,
			allocateDst: true,
		},
	} {
		client, server := getGCMCryptoPair(test.key, t)
		testGCMEncryptionDecryption(client, server, &test, t)
	}
}

func testGCMEncryptRoundtrip(client S2AAeadCrypter, server S2AAeadCrypter, t *testing.T) {
	// Construct a dummy nonce.
	nonce := make([]byte, NonceSize)

	// Encrypt.
	const plaintext = "This is plaintext."
	var err error
	buf := []byte(plaintext)
	buf, err = client.Encrypt(buf[:0], buf, nonce, nil)
	if err != nil {
		t.Fatal("Encrypting with client-side context: unexpected error", err, "\n",
			"Plaintext:", []byte(plaintext))
	}

	// Decrypt first message.
	ciphertext := append([]byte(nil), buf...)
	buf, err = server.Decrypt(buf[:0], buf, nonce, nil)
	if err != nil || string(buf) != plaintext {
		t.Fatal("Decrypting client-side ciphertext with a server-side context did not produce original content:\n",
			"  Original plaintext:", []byte(plaintext), "\n",
			"  Ciphertext:", ciphertext, "\n",
			"  Decryption error:", err, "\n",
			"  Decrypted plaintext:", buf)
	}

	// Decryption fails: replay attack.
	if got, err := server.Decrypt(nil, buf, nonce, nil); err == nil {
		t.Error("Decrypting client-side ciphertext with a client-side context unexpectedly succeeded; want unexpected counter error:\n",
			"  Original plaintext:", []byte(plaintext), "\n",
			"  Ciphertext:", buf, "\n",
			"  Decrypted plaintext:", got)
	}
}

// Test encrypt and decrypt on roundtrip messages for AES-GCM.
func TestAESGCMEncryptRoundtrip(t *testing.T) {
	for _, keySize := range []int{AesGcmKeySize128, AesGcmKeySize256} {
		key := make([]byte, keySize)
		client, server := getGCMCryptoPair(key, t)
		testGCMEncryptRoundtrip(client, server, t)
	}
}

// Test encrypt and decrypt using an invalid key size.
func TestAESGCMInvalidKeySize(t *testing.T) {
	// Use 17 bytes, which is invalid
	key := make([]byte, 17)
	_, err := NewAESGCM(key)
	if err == nil {
		t.Error("expected an error when using invalid key size")
	}
}

func dehex(s string) []byte {
	if len(s) == 0 {
		return make([]byte, 0)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
