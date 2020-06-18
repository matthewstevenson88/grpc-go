package crypter

import (
	"bytes"
	"google.golang.org/grpc/security/s2a/internal/crypter/testutil"
	s2a_proto "google.golang.org/grpc/security/s2a/internal/proto"
	"math"
	"testing"
)

// getHalfConnPair returns a sender/receiver pair of S2A Half Connections.
func getHalfConnPair(ciphersuite s2a_proto.Ciphersuite, trafficSecret []byte, t *testing.T) (S2AHalfConnection, S2AHalfConnection) {
	sender, err := NewHalfConn(ciphersuite, trafficSecret)
	if err != nil {
		t.Fatalf("sender side NewHalfConn(%v, %v) failed: %v", ciphersuite, trafficSecret, err)
	}
	receiver, err := NewHalfConn(ciphersuite, trafficSecret)
	if err != nil {
		t.Fatalf("receiver side NewHalfConn(%v, %v) failed: %v", ciphersuite, trafficSecret, err)
	}
	return sender, receiver
}

// aeadCrypterEqual checks whether the given s2aAeadCrypters encrypt a simple
// string identically.
func aeadCrypterEqual(a s2aAeadCrypter, b s2aAeadCrypter, t *testing.T) bool {
	nonce := make([]byte, nonceSize)
	const plaintext = "This is plaintext"
	ciphertextA, err := a.encrypt(nil, []byte(plaintext), nonce, nil)
	if err != nil {
		t.Errorf("a.encrypt(nil, %v, %v, nil) failed: %v", []byte(plaintext), nonce, err)
	}
	ciphertextB, err := b.encrypt(nil, []byte(plaintext), nonce, nil)
	if err != nil {
		t.Errorf("b.encrypt(nil, %v, %v, nil) failed: %v", []byte(plaintext), nonce, err)
	}
	return bytes.Equal(ciphertextA, ciphertextB)
}

func testHalfConnRoundtrip(sender S2AHalfConnection, receiver S2AHalfConnection, t *testing.T) {
	// Encrypt first message.
	const plaintext = "This is plaintext."
	buf := []byte(plaintext)
	_, err := sender.Encrypt(buf[:0], buf, nil)
	if err != nil {
		t.Fatalf("Encrypt(%v, %v, nil) failed: %v", buf[:0], buf, err)
	}

	// Encrypt second message.
	const plaintext2 = "This is a second plaintext."
	buf2 := []byte(plaintext2)
	ciphertext2, err := sender.Encrypt(buf2[:0], buf2, nil)
	if err != nil {
		t.Fatalf("Encrypt(%v, %v, nil) failed: %v", buf2[:0], buf2, err)
	}

	// Encrypt empty message.
	const plaintext3 = ""
	buf3 := []byte(plaintext3)
	ciphertext3, err := sender.Encrypt(buf3[:0], buf3, nil)
	if err != nil {
		t.Fatalf("Encrypt(%v, %v, nil) failed: %v", buf3[:0], buf3, err)
	}

	// Decryption fails: cannot decrypt second message before first.
	if _, err := receiver.Decrypt(nil, ciphertext2, nil); err == nil {
		t.Errorf("Decrypt(nil, %v, nil) expected an error, received none", ciphertext2)
	}

	// Decrypt second message. This works now because the sequence number was
	// incremented by the previous call to decrypt.
	decryptedPlaintext2, err := receiver.Decrypt(ciphertext2[:0], ciphertext2, nil)
	if err != nil {
		t.Fatalf("Decrypt(%v, %v, nil) failed: %v", ciphertext2[:0], ciphertext2, err)
	}
	if got, want := string(decryptedPlaintext2), plaintext2; got != want {
		t.Fatalf("Decrypt(%v, %v, nil) = %v, want %v", ciphertext2[:0], ciphertext2, got, want)
	}

	// Decrypt third (empty) message.
	decryptedPlaintext3, err := receiver.Decrypt(ciphertext3[:0], ciphertext3, nil)
	if err != nil {
		t.Fatalf("Decrypt(%v, %v, nil) failed: %v", ciphertext3[:0], ciphertext3, err)
	}
	if got, want := string(decryptedPlaintext3), plaintext3; got != want {
		t.Fatalf("Decrypt(%v, %v, nil) = %v, want %v", ciphertext3[:0], ciphertext3, got, want)
	}

	// Decryption fails: same message decrypted again.
	if _, err := receiver.Decrypt(nil, ciphertext3, nil); err == nil {
		t.Errorf("Decrypt(nil, %v, nil) expected an error, received none", ciphertext3)
	}
}

func TestGetAndIncrementSequence(t *testing.T) {
	for _, tc := range []struct {
		desc                     string
		counter, expectedCounter uint64
		shouldOverflow           bool
	}{
		{
			desc:            "basic 1",
			counter:         0,
			expectedCounter: 1,
		},
		{
			desc:            "basic 2",
			counter:         123,
			expectedCounter: 124,
		},
		{
			desc:            "almost overflow",
			counter:         math.MaxUint64 - 1,
			expectedCounter: math.MaxUint64,
		},
		{
			desc:           "max overflow",
			counter:        math.MaxUint64,
			shouldOverflow: true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			hc := S2AHalfConnection{sequence: counter{val: tc.counter}}
			// Make first getAndIncrement call. This should return the same value
			// that was given.
			value, err := hc.getAndIncrementSequence()
			if err != nil {
				t.Errorf("S2A counter starting with %v, hc.getAndIncrementSequence() failed: %v", tc.counter, err)
			}
			if value != tc.counter {
				t.Errorf("S2A counter starting with %v, hc.getAndIncrementSequence() = %v, want %v", tc.counter, value, tc.counter)
			}

			// Make second getAndIncrement call. This should verify that the first
			// getAndIncrement call succeeded in incrementing the value.
			value, err = hc.getAndIncrementSequence()
			if got, want := err == nil, !tc.shouldOverflow; got != want {
				t.Errorf("S2A counter starting with %v, val()=(err=nil)=%v, want %v", tc.counter, got, want)
			}
			if got, want := value, tc.expectedCounter; err == nil && got != want {
				t.Errorf("S2A counter starting with %v, val() = %v, want %v", tc.counter, got, want)
			}
		})
	}
}

func TestMaskedNonce(t *testing.T) {
	for _, tc := range []struct {
		desc        string
		nonce       []byte
		sequence    uint64
		maskedNonce []byte
	}{
		{
			desc:        "zero nonce and zero sequence",
			nonce:       testutil.Dehex("000000000000000000000000"),
			sequence:    0,
			maskedNonce: testutil.Dehex("000000000000000000000000"),
		},
		{
			desc:        "max nonce and zero sequence",
			nonce:       testutil.Dehex("ffffffffffffffffffffffff"),
			sequence:    0,
			maskedNonce: testutil.Dehex("ffffffffffffffffffffffff"),
		},
		{
			desc:        "zero nonce and max sequence",
			nonce:       testutil.Dehex("000000000000000000000000"),
			sequence:    math.MaxUint64,
			maskedNonce: testutil.Dehex("00000000ffffffffffffffff"),
		},
		{
			desc:        "max nonce and max sequence",
			nonce:       testutil.Dehex("ffffffffffffffffffffffff"),
			sequence:    math.MaxUint64,
			maskedNonce: testutil.Dehex("ffffffff0000000000000000"),
		},
		{
			desc:        "non-zero nonce and non-zero sequence",
			nonce:       testutil.Dehex("010101010101010101010101"),
			sequence:    1,
			maskedNonce: testutil.Dehex("010101010101010101010100"),
		},
		{
			desc:        "cancel out",
			nonce:       testutil.Dehex("00000000ffffffffffffffff"),
			sequence:    math.MaxUint64,
			maskedNonce: testutil.Dehex("000000000000000000000000"),
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			hc := S2AHalfConnection{nonce: tc.nonce}
			if got, want := hc.maskedNonce(tc.sequence), tc.maskedNonce; !bytes.Equal(got, want) {
				t.Errorf("hc.maskedNonce(%v) = %v, want %v", tc.sequence, got, want)
			}
		})
	}
}

func TestNewHalfConn(t *testing.T) {
	for _, tc := range []struct {
		desc                      string
		ciphersuite               s2a_proto.Ciphersuite
		trafficSecret, key, nonce []byte
		shouldFail                bool
	}{
		{
			desc:          "AES-128-GCM-SHA256 invalid traffic secret",
			ciphersuite:   s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("00"),
			shouldFail:    true,
		},
		{
			desc:          "AES-128-GCM-SHA256 valid",
			ciphersuite:   s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			key:           testutil.Dehex("c3ae7509cfced2b803a6186956cda79f"),
			nonce:         testutil.Dehex("b5803d82ad8854d2e598187f"),
		},
		{
			desc:          "AES-256-GCM-SHA384 invalid traffic secret",
			ciphersuite:   s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("00"),
			shouldFail:    true,
		},
		{
			desc:          "AES-256-GCM-SHA384 valid",
			ciphersuite:   s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			key:           testutil.Dehex("dac731ae4866677ed2f65c490e18817be5cbbbd03f597ad59041c117b731109a"),
			nonce:         testutil.Dehex("4db152d27d180b1ee48fa89d"),
		},
		{
			desc:          "CHACHA20-POLY1305-SHA256 invalid traffic secret",
			ciphersuite:   s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("00"),
			shouldFail:    true,
		},
		{
			desc:          "CHACHA20-POLY1305-SHA256 valid",
			ciphersuite:   s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			key:           testutil.Dehex("130e2000508ace00ef265e172d09892e467256cb90dad9de99543cf548be6a8b"),
			nonce:         testutil.Dehex("b5803d82ad8854d2e598187f"),
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			hc, err := NewHalfConn(tc.ciphersuite, tc.trafficSecret)
			if got, want := err == nil, !tc.shouldFail; got != want {
				t.Errorf("NewHalfConn(%v, %v)=(err=nil)=%v, want %v", tc.ciphersuite, tc.trafficSecret, got, want)
			}
			if err != nil {
				return
			}
			// Check that the traffic secret wasn't changed.
			if got, want := hc.trafficSecret, tc.trafficSecret; !bytes.Equal(got, want) {
				t.Errorf("NewHalfConn(%v, %v).trafficSecret=%v, want %v", tc.ciphersuite, tc.trafficSecret, got, want)
			}
			if got, want := hc.nonce, tc.nonce; !bytes.Equal(got, want) {
				t.Errorf("NewHalfConn(%v, %v).nonce=%v, want %v", tc.ciphersuite, tc.trafficSecret, got, want)
			}
			cs, err := newCiphersuite(tc.ciphersuite)
			if err != nil {
				t.Errorf("newCipherSuite(%v) failed: %v", tc.ciphersuite, err)
			}
			aeadCrypter, err := cs.aeadCrypter(tc.key)
			if err != nil {
				t.Errorf("cs.aeadCrypter(%v) failed: %v", tc.key, err)
			}
			if got, want := hc.aeadCrypter, aeadCrypter; !aeadCrypterEqual(got, want, t) {
				t.Errorf("aeadCrypterEqual returned false, expected true")
			}
		})
	}
}

func TestS2AHalfConnectionRoundtrip(t *testing.T) {
	for _, tc := range []struct {
		ciphersuite   s2a_proto.Ciphersuite
		trafficSecret []byte
	}{
		{
			ciphersuite:   s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
		},
		{
			ciphersuite:   s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
		},
		{
			ciphersuite:   s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
		},
	} {
		t.Run(tc.ciphersuite.String(), func(t *testing.T) {
			sender, receiver := getHalfConnPair(tc.ciphersuite, tc.trafficSecret, t)
			testHalfConnRoundtrip(sender, receiver, t)
		})
	}
}

func TestS2AHalfConnectionUpdateKey(t *testing.T) {
	for _, tc := range []struct {
		ciphersuite                                      s2a_proto.Ciphersuite
		trafficSecret, advancedTrafficSecret, key, nonce []byte
	}{
		{
			ciphersuite:           s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret:         testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			advancedTrafficSecret: testutil.Dehex("f38b9455ea5871235a69fc37610c6ca1215779e66b45a047d7390111e00081c4"),
			key:                   testutil.Dehex("07dfdfca2fc3f015b6e51e579679b503"),
			nonce:                 testutil.Dehex("79fdebc61b5fb9d9a34d9406"),
		},
		{
			ciphersuite:           s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret:         testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			advancedTrafficSecret: testutil.Dehex("016c835db664beb5526a9bb3d9a4fba63e67255dcfa460a114d9f1ef9a9a1f685a518739f557d0e66fdb89bdafa26257"),
			key:                   testutil.Dehex("4ee0f141c9a497a1db6f1ee0995248e804406fe39f35bcdff9f386048108bef1"),
			nonce:                 testutil.Dehex("90f241fbc9f9f55100168d8b"),
		},
		{
			ciphersuite:           s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret:         testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			advancedTrafficSecret: testutil.Dehex("f38b9455ea5871235a69fc37610c6ca1215779e66b45a047d7390111e00081c4"),
			key:                   testutil.Dehex("18b61f93ee2d927d2f478f2220409738affb0092602d0812c96b965323e30878"),
			nonce:                 testutil.Dehex("79fdebc61b5fb9d9a34d9406"),
		},
	} {
		t.Run(tc.ciphersuite.String(), func(t *testing.T) {
			hc, err := NewHalfConn(tc.ciphersuite, tc.trafficSecret)
			if err != nil {
				t.Fatalf("NewHalfConn(%v, %v) failed: %v", tc.ciphersuite, tc.trafficSecret, err)
			}
			if err := hc.UpdateKey(); err != nil {
				t.Fatalf("hc.updateKey() failed: %v", err)
			}
			if got, want := hc.trafficSecret, tc.advancedTrafficSecret; !bytes.Equal(got, want) {
				t.Errorf("hc.trafficSecret = %v, want %v", got, want)
			}
			if got, want := hc.nonce, tc.nonce; !bytes.Equal(got, want) {
				t.Errorf("hc.nonce = %v, want %v", got, want)
			}
			cs, err := newCiphersuite(tc.ciphersuite)
			if err != nil {
				t.Errorf("newCipherSuite(%v) failed: %v", tc.ciphersuite, err)
			}
			aeadCrypter, err := cs.aeadCrypter(tc.key)
			if err != nil {
				t.Errorf("cs.aeadCrypter(%v) failed: %v", tc.key, err)
			}
			if got, want := hc.aeadCrypter, aeadCrypter; !aeadCrypterEqual(got, want, t) {
				t.Errorf("aeadCrypterEqual returned false, expected true")
			}
		})
	}
}
