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
	"fmt"
	"testing"

	"google.golang.org/grpc/security/s2a/internal/crypter/testutil"
)

// getGCMCryptoPair outputs a sender/receiver pair on CHACHA-POLY.
func getPOLYCryptoPair(key []byte, t *testing.T) (s2aAeadCrypter, s2aAeadCrypter) {
	sender, err := newCHACHAPOLY(key)
	if err != nil {
		t.Fatalf("newCHACHAPOLY(ClientSide, key) = %v", err)
	}
	receiver, err := newCHACHAPOLY(key)
	if err != nil {
		t.Fatalf("newCHACHAPOLY(ServerSide, key) = %v", err)
	}
	return sender, receiver
}

func wycheProofTestVectorFilterCCP(testGroup testutil.TestGroup) bool {
	return testGroup.IVSize != 96 ||
		(testGroup.KeySize != 256) ||
		testGroup.TagSize != 128
}

func testPOLYEncryptionDecryption(sender s2aAeadCrypter, receiver s2aAeadCrypter, test *testutil.CryptoTestVector, t *testing.T) {
	// Ciphertext is: encrypted text + tag.
	ciphertext := append(test.Ciphertext, test.Tag...)

	// Encrypt.
	var dst []byte
	if test.AllocateDst {
		dst = make([]byte, len(test.Plaintext)+sender.tagSize())
	}
	got, err := sender.encrypt(dst[:0], test.Plaintext, test.Nonce, test.Aad)
	if isFailure(test.Result, err, got, ciphertext) {
		t.Errorf("key=%v\nplaintext=%v\nnonce=%v\naad=%v\nEncrypt = %v, %v\nwant: %v",
			test.Key, test.Plaintext, test.Nonce, test.Aad, got, err, ciphertext)
	}

	// Decrypt.
	got, err = receiver.decrypt(nil, ciphertext, test.Nonce, test.Aad)
	if isFailure(test.Result, err, got, test.Plaintext) {
		t.Errorf("key=%v\nciphertext=%v\nnonce=%v\naad=%v\nDecrypt = %v, %v\nwant: %v\n",
			test.Key, ciphertext, test.Nonce, test.Aad, got, err, test.Plaintext)
	}
}

func testPOLYEncryptRoundtrip(sender s2aAeadCrypter, receiver s2aAeadCrypter, t *testing.T) {
	// Construct a dummy nonce.
	nonce := make([]byte, nonceSize)

	// Encrypt.
	const plaintext = "This is plaintext."
	var err error
	buf := []byte(plaintext)
	ciphertext, err := sender.encrypt(buf[:0], buf, nonce, nil)
	if err != nil {
		t.Fatal("Encrypting with sender-side context: unexpected error", err, "\n",
			"Plaintext:", []byte(plaintext))
	}

	// Decrypt first message.
	decryptedPlaintext, err := receiver.decrypt(ciphertext[:0], ciphertext, nonce, nil)
	if err != nil || string(decryptedPlaintext) != plaintext {
		t.Fatal("Decrypting sender-side ciphertext with a receiver-side context did not produce original content:\n",
			"  Original plaintext:", []byte(plaintext), "\n",
			"  Ciphertext:", ciphertext, "\n",
			"  Decryption error:", err, "\n",
			"  Decrypted plaintext:", decryptedPlaintext)
	}

	// Decryption fails: replay attack.
	if got, err := receiver.decrypt(nil, buf, nonce, nil); err == nil {
		t.Error("Decrypting sender-side ciphertext with a sender-side context unexpectedly succeeded; want unexpected counter error:\n",
			"  Original plaintext:", []byte(plaintext), "\n",
			"  Ciphertext:", buf, "\n",
			"  Decrypted plaintext:", got)
	}
}

// Test encrypt and decrypt using an invalid key size.
func TestCHACHAPOLYInvalidKeySize(t *testing.T) {
	// Use 17 bytes, which is invalid
	key := make([]byte, 17)
	if _, err := newCHACHAPOLY(key); err == nil {
		t.Error("expected an error when using invalid key size")
	}
}

// Test update key for CHACHA-POLY  using a key with different size from the initial
// key.
func TestCHACHAPOLYKeySizeUpdate(t *testing.T) {
	for _, tc := range []struct {
		desc          string
		updateKeySize int
	}{
		{"invalid key size update", 17},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			key := make([]byte, chachaKeySize256)
			crypter, err := newCHACHAPOLY(key)
			if err != nil {
				t.Fatalf("NewAESGCM(keySize=%v) failed, err: %v", chachaKeySize256, err)
			}

			// Update the key with a new one which is a different from the original.
			newKey := make([]byte, tc.updateKeySize)
			if err = crypter.updateKey(newKey); err == nil {
				t.Fatal("UpdateKey should fail with invalid key size error")
			}
		})
	}
}

// Test Encrypt/Decrypt using an invalid nonce size.
func TestCHACHAPOLYEncryptDecryptInvalidNonce(t *testing.T) {
	key := make([]byte, chachaKeySize256)
	crypter, err := newCHACHAPOLY(key)
	if err != nil {
		t.Fatalf("NewCHACHAPOLY(keySize=%v) failed, err: %v", chachaKeySize256, err)
	}
	// Construct nonce with invalid size.
	nonce := make([]byte, 1)
	if _, err = crypter.encrypt(nil, nil, nonce, nil); err == nil {
		t.Errorf("Encrypt should fail due to invalid nonce size")
	}
	if _, err = crypter.decrypt(nil, nil, nonce, nil); err == nil {
		t.Fatalf("Decrypt should fail due to invalid nonce size")
	}
}

// Test encrypt and decrypt on roundtrip messages for AES-GCM.
func TestCHACHAPOLYEncryptRoundtrip(t *testing.T) {
	for _, keySize := range []int{chachaKeySize256} {
		key := make([]byte, keySize)
		sender, receiver := getPOLYCryptoPair(key, t)
		testPOLYEncryptRoundtrip(sender, receiver, t)
	}
}

// Test encrypt and decrypt on roundtrip messages for AES-GCM using an updated
// key.
func TestCHACHAPOLYUpdatedKey(t *testing.T) {
	for _, keySize := range []int{chachaKeySize256} {
		key := make([]byte, keySize)
		sender, receiver := getPOLYCryptoPair(key, t)
		// Update the key with a new one which is different from the original.
		newKey := make([]byte, keySize)
		newKey[0] = '\xbd'
		if err := sender.updateKey(newKey); err != nil {
			t.Fatalf("sender UpdateKey failed with: %v", err)
		}
		if err := receiver.updateKey(newKey); err != nil {
			t.Fatalf("receiver UpdateKey failed with: %v", err)
		}
		testPOLYEncryptRoundtrip(sender, receiver, t)
	}
}

func TestWycheProofTestVectorsCCP(t *testing.T) {
	for _, test := range testutil.ParseWycheProofTestVectors(
		"testdata/chacha_poly_wycheproof.json",
		wycheProofTestVectorFilterCCP,
		t,
	) {
		t.Run(fmt.Sprintf("%d/%s", test.ID, test.Desc), func(t *testing.T) {
			// Test encryption and decryption for AES-GCM.
			sender, receiver := getPOLYCryptoPair(test.Key, t)
			testPOLYEncryptionDecryption(sender, receiver, &test, t)
		})
	}
}

//Test CHACHA-POLY with RFC test vectors.
func TestCHACHAPOLYRFC(t *testing.T) {
	for _, test := range []testutil.CryptoTestVector{
		{
			Desc:       "RFC test vector 1",
			Key:        testutil.Dehex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
			Nonce:      testutil.Dehex("070000004041424344454647"),
			Aad:        testutil.Dehex("50515253c0c1c2c3c4c5c6c7"),
			Plaintext:  testutil.Dehex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"),
			Ciphertext: testutil.Dehex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"),
			Result:     testutil.ValidResult,
		},
		{
			Desc:       "RFC test vector 2",
			Key:        testutil.Dehex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"),
			Nonce:      testutil.Dehex("000000000102030405060708"),
			Aad:        testutil.Dehex("f33388860000000000004e91"),
			Plaintext:  testutil.Dehex("496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d"),
			Ciphertext: testutil.Dehex("64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709beead9d67890cbb22392336fea1851f38"),
			Result:     testutil.ValidResult,
		},
	} {
		t.Run(fmt.Sprintf("%s", test.Desc), func(t *testing.T) {
			// Test encryption and decryption for CHACHA-POLY
			sender, receiver := getPOLYCryptoPair(test.Key, t)
			testPOLYEncryptionDecryption(sender, receiver, &test, t)
		})
	}
}
