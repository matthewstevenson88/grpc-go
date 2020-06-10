package crypter

import (
	"fmt"
	"google.golang.org/grpc/security/s2a/internal/crypter/testutil"
	s2a_proto "google.golang.org/grpc/security/s2a/internal/proto"
	"testing"
)

// getHalfConnPair returns a sender/receiver pair of S2A Half Connections.
func getHalfConnPair(ciphersuite s2a_proto.Ciphersuite, trafficSecret []byte, t *testing.T) (s2aHalfConnection, s2aHalfConnection) {
	sender, err := newHalfConn(ciphersuite, trafficSecret)
	if err != nil {
		t.Fatalf("sender side newHalfConn(%v, %v) failed, err = %v", ciphersuite, trafficSecret, err)
	}
	receiver, err := newHalfConn(ciphersuite, trafficSecret)
	if err != nil {
		t.Fatalf("receiver side newHalfConn(%v, %v) failed, err = %v", ciphersuite, trafficSecret, err)
	}
	return sender, receiver
}

func testHalfConnRoundtrip(sender s2aHalfConnection, receiver s2aHalfConnection, t *testing.T) {
	// Encrypt first message.
	const plaintext = "This is plaintext."
	buf := []byte(plaintext)
	_, err := sender.encrypt(buf[:0], buf, nil)
	if err != nil {
		t.Fatalf("encrypt(%v, %v, nil) failed, err = %v", buf[:0], buf, err)
	}

	// Encrypt second message.
	const plaintext2 = "This is a second plaintext."
	buf2 := []byte(plaintext2)
	ciphertext2, err := sender.encrypt(buf2[:0], buf2, nil)
	if err != nil {
		t.Fatalf("encrypt(%v, %v, nil) failed, err = %v", buf2[:0], buf2, err)
	}

	// Decryption fails: cannot decrypt second message before first.
	if _, err := receiver.decrypt(nil, ciphertext2, nil); err == nil {
		t.Errorf("decrypt(nil, %v, nil) expected an error, received none", ciphertext2)
	}

	// Decrypt second message. This works now because the sequence number was
	// incremented by the previous call to decrypt.
	decryptedPlaintext2, err := receiver.decrypt(ciphertext2[:0], ciphertext2, nil)
	if err != nil {
		t.Fatalf("decrypt(%v, %v, nil) failed, err = %v", ciphertext2[:0], ciphertext2, err)
	}
	if got, want := string(decryptedPlaintext2), plaintext2; got != want {
		t.Fatalf("decrypt(%v, %v, nil) = %v, want %v", ciphertext2[:0], ciphertext2, got, want)
	}

	// Decryption fails: same message decrypted again.
	if _, err := receiver.decrypt(nil, ciphertext2, nil); err == nil {
		t.Errorf("decrypt(nil, %v, nil) expected an error, received none", ciphertext2)
	}
}

func TestNewHalfConn(t *testing.T) {
	for _, tc := range []struct {
		ciphersuite   s2a_proto.Ciphersuite
		trafficSecret []byte
		shouldFail    bool
	}{
		{
			ciphersuite:   s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("00"),
			shouldFail:    true,
		},
		{
			ciphersuite:   s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
		},
		{
			ciphersuite:   s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("00"),
			shouldFail:    true,
		},
		{
			ciphersuite:   s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
		},
		{
			ciphersuite:   s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("00"),
			shouldFail:    true,
		},
		{
			ciphersuite:   s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
		},
	} {
		t.Run(fmt.Sprintf("%v/shouldFail=%v", tc.ciphersuite.String(), tc.shouldFail), func(t *testing.T) {
			// TODO(rnkim): Remove below.
			if tc.ciphersuite == s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256 {
				return
			}

			_, err := newHalfConn(tc.ciphersuite, tc.trafficSecret)
			if got, want := err == nil, !tc.shouldFail; got != want {
				t.Errorf("newHalfConn(%v, %v)=(err=nil)=%v, want %v", tc.ciphersuite, tc.trafficSecret, got, want)
			}

		})
	}
}

func TestS2AHalfConnectionEncryptDecrypt(t *testing.T) {
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
			// TODO(rnkim): Remove below.
			if tc.ciphersuite == s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256 {
				return
			}
			sender, receiver := getHalfConnPair(tc.ciphersuite, tc.trafficSecret, t)
			testHalfConnRoundtrip(sender, receiver, t)
		})
	}

}

func TestS2AHalfConnectionUpdateKey(t *testing.T) {

}
