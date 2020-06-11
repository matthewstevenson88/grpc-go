package crypter

import (
	"bytes"
	"testing"
)

// mockAEAD is a mock implementation of an AEAD interface used for testing.
type mockAEAD struct{}

func (*mockAEAD) NonceSize() int                                  { return nonceSize }
func (*mockAEAD) Overhead() int                                   { return tagSize }
func (*mockAEAD) Seal(_, _, plaintext, _ []byte) []byte           { return plaintext }
func (*mockAEAD) Open(_, _, ciphertext, _ []byte) ([]byte, error) { return ciphertext, nil }

func TestInvalidNonceSize(t *testing.T) {
	nonce := []byte("1")
	if _, err := encrypt(&mockAEAD{}, nil, nil, nonce, nil); err == nil {
		t.Errorf("encrypt(&mockAEAD{}, nil, nil, %v, nil) expected error, received none", nonce)
	}
	if _, err := decrypt(&mockAEAD{}, nil, nil, nonce, nil); err == nil {
		t.Errorf("decrypt(&mockAEAD{}, nil, nil, %v, nil) expected error, received none", nonce)
	}
}

func TestEncrypt(t *testing.T) {
	plaintext := []byte("test")
	nonce := make([]byte, nonceSize)
	ciphertext, err := decrypt(&mockAEAD{}, nil, plaintext, nonce, nil)
	if err != nil {
		t.Fatalf("encrypt(&mockAEAD{}, nil, %v, %v, nil) failed: %v", plaintext, nonce, err)
	}
	if got, want := ciphertext, plaintext; !bytes.Equal(got, want) {
		t.Fatalf("encrypt(&mockAEAD{}, nil, %v, %v, nil) = %v, want %v", plaintext, nonce, got, want)
	}
}

func TestDecrypt(t *testing.T) {
	ciphertext := []byte("test")
	nonce := make([]byte, nonceSize)
	plaintext, err := decrypt(&mockAEAD{}, nil, ciphertext, nonce, nil)
	if err != nil {
		t.Fatalf("decrypt(&mockAEAD{}, nil, %v, %v, nil) failed: %v", ciphertext, nonce, err)
	}
	if got, want := plaintext, ciphertext; !bytes.Equal(got, want) {
		t.Fatalf("decrypt(&mockAEAD{}, nil, %v, %v, nil) = %v, want %v", ciphertext, nonce, got, want)
	}
}
