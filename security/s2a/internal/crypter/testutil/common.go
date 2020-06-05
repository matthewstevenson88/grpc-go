package testutil

import (
	"encoding/hex"
)

// Constants indicating whether the test vector is valid or not.
const (
	ValidResult   = "valid"
	InvalidResult = "invalid"
)

// CryptoTestVector is a struct representing a test vector for an s2aAeadCrypter
// instance.
type CryptoTestVector struct {
	Desc                                        string
	ID                                          int
	Key, Plaintext, Ciphertext, Tag, Nonce, Aad []byte
	Result                                      string
	AllocateDst                                 bool
}

// TestVector is a struct for a WycheProof test vector.
type TestVector struct {
	TcID    int    `json:"tcId"`
	Comment string `json:"comment"`
	Key     string `json:"key"`
	IV      string `json:"iv"`
	Aad     string `json:"aad"`
	Msg     string `json:"msg"`
	Ct      string `json:"ct"`
	Tag     string `json:"tag"`
	Result  string `json:"result"`
}

// TestGroup is a struct for a WycheProof test group.
type TestGroup struct {
	IVSize  int          `json:"ivSize"`
	KeySize int          `json:"keySize"`
	TagSize int          `json:"tagSize"`
	Tests   []TestVector `json:"tests"`
}

// TestFile is a struct for a WycheProof test file.
type TestFile struct {
	TestGroups []TestGroup `json:"testGroups"`
}

func Dehex(s string) []byte {
	if len(s) == 0 {
		return make([]byte, 0)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
