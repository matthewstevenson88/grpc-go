package testutil

import (
	"encoding/json"
	"os"
	"testing"
)

// ParseWycheProofTestVectors takes a path to a WycheProof test vector, a test
// group filter, and returns the resulting CryptoTestVector. The test group
// filter will be used to filter out unsupported test inputs.
func ParseWycheProofTestVectors(
	jsonFilePath string,
	testGroupFilter func(TestGroup) bool,
	t *testing.T,
) []CryptoTestVector {
	jsonFile, err := os.Open(jsonFilePath)
	if err != nil {
		t.Fatalf("failed to open wycheproof json test vectors file: %v", err)
	}
	defer jsonFile.Close()

	dec := json.NewDecoder(jsonFile)

	var tf TestFile
	err = dec.Decode(&tf)
	if err != nil {
		t.Fatalf("failed to decode wycheproof json file: %v", err)
	}

	var testVectors []CryptoTestVector
	for _, testGroup := range tf.TestGroups {
		// Skip over unsupported inputs.
		if testGroupFilter(testGroup) {
			continue
		}
		for _, test := range testGroup.Tests {
			testVectors = append(testVectors, CryptoTestVector{
				Key:         Dehex(test.Key),
				Plaintext:   Dehex(test.Msg),
				Ciphertext:  Dehex(test.Ct),
				Tag:         Dehex(test.Tag),
				Nonce:       Dehex(test.Iv),
				Aad:         Dehex(test.Aad),
				Result:      test.Result,
				Comment:     test.Comment,
				Id:          test.TcId,
				AllocateDst: true,
			})
		}
	}

	return testVectors
}
