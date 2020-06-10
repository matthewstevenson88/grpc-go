package crypter

import (
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	s2a_proto "google.golang.org/grpc/security/s2a/internal/proto"
	"hash"
	"sync"
)

const (
	tls13Key    = "tls13 key"
	tls13Nonce  = "tls13 iv"
	tls13Update = "tls13 upd"
)

type s2aHalfConnection struct {
	cs            ciphersuite
	h             func() hash.Hash
	aeadCrypter   s2aAeadCrypter
	expander      hkdfExpander
	seqCounter    counter
	mutex         sync.Mutex
	trafficSecret []byte
	nonce         []byte
}

func newHalfConn(ciphersuite s2a_proto.Ciphersuite, trafficSecret []byte) (s2aHalfConnection, error) {
	cs := newCiphersuite(ciphersuite)
	if cs.trafficSecretSize() != len(trafficSecret) {
		return s2aHalfConnection{}, fmt.Errorf("supplied traffic secret must be %v bytes, given: %v", cs.trafficSecretSize(), trafficSecret)
	}

	hc := s2aHalfConnection{cs: cs, h: cs.hashFunction(), expander: &defaultHKDFExpander{}, seqCounter: newCounter()}

	key, err := hc.deriveSecret(trafficSecret, []byte(tls13Key), hc.cs.keySize())
	if err != nil {
		return s2aHalfConnection{}, fmt.Errorf("hc.deriveSecret(h, %v, %v, %v) failed with error: %v", trafficSecret, tls13Key, hc.cs.keySize(), err)
	}

	hc.nonce, err = hc.deriveSecret(trafficSecret, []byte(tls13Nonce), hc.cs.nonceSize())
	if err != nil {
		return s2aHalfConnection{}, fmt.Errorf("hc.deriveSecret(h, %v, %v, %v) failed with error: %v", trafficSecret, tls13Nonce, hc.cs.nonceSize(), err)
	}

	hc.aeadCrypter, err = cs.aeadCrypter(key)
	if err != nil {
		return s2aHalfConnection{}, fmt.Errorf("cs.aeadCrypter(%v) failed with error: %v", key, err)
	}
	return hc, nil
}

// encrypt encrypts the plaintext and computes the tag of dst and plaintext.
// dst and plaintext may fully overlap or not at all.
func (hc *s2aHalfConnection) encrypt(dst, plaintext, aad []byte) ([]byte, error) {
	hc.mutex.Lock()
	sequence, err := hc.getAndIncrementSequence()
	if err != nil {
		hc.mutex.Unlock()
		return nil, err
	}
	nonce := hc.maskedNonce(sequence)
	crypter := hc.aeadCrypter
	hc.mutex.Unlock()
	return crypter.encrypt(dst, plaintext, nonce, aad)
}

// decrypt decrypts ciphertext and verifies the tag. dst and ciphertext may
// fully overlap or not at all.
func (hc *s2aHalfConnection) decrypt(dst, ciphertext, aad []byte) ([]byte, error) {
	hc.mutex.Lock()
	sequence, err := hc.getAndIncrementSequence()
	if err != nil {
		hc.mutex.Unlock()
		return nil, err
	}
	nonce := hc.maskedNonce(sequence)
	crypter := hc.aeadCrypter
	hc.mutex.Unlock()
	return crypter.decrypt(dst, ciphertext, nonce, aad)
}

// updateKey updates the traffic secret key, as specified in
// https://tools.ietf.org/html/rfc8446#section-7.2
func (hc *s2aHalfConnection) updateKey() error {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	var err error
	hc.trafficSecret, err = hc.deriveSecret(hc.trafficSecret, []byte(tls13Update), hc.cs.trafficSecretSize())
	if err != nil {
		return fmt.Errorf("hc.deriveSecret(h, %v, %v, %v) failed with error: %v", hc.trafficSecret, tls13Update, hc.cs.trafficSecretSize(), err)
	}

	key, err := hc.deriveSecret(hc.trafficSecret, []byte(tls13Key), hc.cs.keySize())
	if err != nil {
		return fmt.Errorf("hc.deriveSecret(h, %v, %v, %v) failed with error: %v", hc.trafficSecret, tls13Key, hc.cs.keySize(), err)
	}

	hc.nonce, err = hc.deriveSecret(hc.trafficSecret, []byte(tls13Nonce), hc.cs.nonceSize())
	if err != nil {
		return fmt.Errorf("hc.deriveSecret(h, %v, %v, %v) failed with error: %v", hc.trafficSecret, tls13Nonce, hc.cs.nonceSize(), err)
	}

	err = hc.aeadCrypter.updateKey(key)
	if err != nil {
		return fmt.Errorf("hc.aeadCrypter.updateKey(%v) failed with error: %v", key, err)
	}

	hc.seqCounter.reset()
	return nil
}

func (hc *s2aHalfConnection) getAndIncrementSequence() (uint64, error) {
	sequence, err := hc.seqCounter.value()
	if err != nil {
		return 0, err
	}
	hc.seqCounter.increment()
	return sequence, nil
}

func (hc *s2aHalfConnection) maskedNonce(sequence uint64) []byte {
	nonce := make([]byte, len(hc.nonce))
	copy(nonce, hc.nonce)
	// Note that the 8 represents the size of a uint64 in bytes.
	for i := 0; i < 8; i++ {
		nonce[nonceSize-8+i] ^= byte(sequence >> uint64(56-8*i))
	}
	return nonce
}

// deriveSecret implements Derive-Secret specified in
// https://tools.ietf.org/html/rfc8446#section-7.1.
func (hc *s2aHalfConnection) deriveSecret(secret, label []byte, length int) ([]byte, error) {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(label)
	})
	hkdfLabelBytes, err := hkdfLabel.Bytes()
	if err != nil {
		return nil, fmt.Errorf("deriveSecret failed with error: %v", err)
	}
	return hc.expander.expand(hc.h, secret, hkdfLabelBytes, length)
}
