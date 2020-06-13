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
	tls13Update = "tls13 traffic upd"
)

type S2AHalfConnection struct {
	cs ciphersuite
	// TODO(rnkim): Add hash function to expander constructor.
	h           func() hash.Hash
	aeadCrypter s2aAeadCrypter
	expander    hkdfExpander
	sequence    counter
	// mutex guards sequence, aeadCrypter, trafficSecret, and nonce.
	mutex         sync.Mutex
	trafficSecret []byte
	nonce         []byte
}

// NewHalfConn creates a new instance of S2AHalfConnection.
func NewHalfConn(ciphersuite s2a_proto.Ciphersuite, trafficSecret []byte) (S2AHalfConnection, error) {
	cs := newCiphersuite(ciphersuite)
	if cs.trafficSecretSize() != len(trafficSecret) {
		return S2AHalfConnection{}, fmt.Errorf("supplied traffic secret must be %v bytes, given: %v bytes", cs.trafficSecretSize(), len(trafficSecret))
	}

	hc := S2AHalfConnection{cs: cs, h: cs.hashFunction(), expander: &defaultHKDFExpander{}, sequence: newCounter(), trafficSecret: trafficSecret}

	var err error
	if err = hc.updateCrypterAndNonce(hc.trafficSecret, false /* updateCrypterKey */); err != nil {
		return S2AHalfConnection{}, fmt.Errorf("failed to create half connection using traffic secret: %v", err)
	}

	return hc, nil
}

// Encrypt encrypts the plaintext and computes the tag of dst and plaintext.
// dst and plaintext may fully overlap or not at all. Note that the sequence
// number will still be incremented on failure, unless the sequence has
// overflowed.
func (hc *S2AHalfConnection) Encrypt(dst, plaintext, aad []byte) ([]byte, error) {
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

// Decrypt decrypts ciphertext and verifies the tag. dst and ciphertext may
// fully overlap or not at all. Note that the sequence number will still be
// incremented on failure, unless the sequence has overflowed.
func (hc *S2AHalfConnection) Decrypt(dst, ciphertext, aad []byte) ([]byte, error) {
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

// UpdateKey advances the traffic secret key, as specified in
// https://tools.ietf.org/html/rfc8446#section-7.2. In addition, it derives
// a new key and nonce, and resets the sequence number.
func (hc *S2AHalfConnection) UpdateKey() error {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	var err error
	hc.trafficSecret, err = hc.deriveSecret(hc.trafficSecret, []byte(tls13Update), hc.cs.trafficSecretSize())
	if err != nil {
		return fmt.Errorf("failed to advance traffic secret: %v", err)
	}

	if err = hc.updateCrypterAndNonce(hc.trafficSecret, true /* updateCrypterKey */); err != nil {
		return fmt.Errorf("failed to update half connection: %v", err)
	}

	hc.sequence.reset()
	return nil
}

// updateCrypterAndNonce takes a new traffic secret and updates the crypter
// and nonce. The updateCrypterKey flag determines whether a new AEAD crypter
// is created or the existing one is updated with a new key. The
// updateCrypterKey flag should only be set to false when called by the
// constructor.
func (hc *S2AHalfConnection) updateCrypterAndNonce(newTrafficSecret []byte, updateCrypterKey bool) error {
	key, err := hc.deriveSecret(newTrafficSecret, []byte(tls13Key), hc.cs.keySize())
	if err != nil {
		return fmt.Errorf("failed to update key: %v", err)
	}

	hc.nonce, err = hc.deriveSecret(newTrafficSecret, []byte(tls13Nonce), hc.cs.nonceSize())
	if err != nil {
		return fmt.Errorf("failed to update nonce: %v", err)
	}

	if updateCrypterKey {
		err = hc.aeadCrypter.updateKey(key)
		if err != nil {
			return fmt.Errorf("failed to update AEAD crypter: %v", err)
		}
	} else {
		hc.aeadCrypter, err = hc.cs.aeadCrypter(key)
		if err != nil {
			return fmt.Errorf("failed to create AEAD crypter: %v", err)
		}
	}
	return nil
}

// getAndIncrement returns the current sequence number and increments it.
func (hc *S2AHalfConnection) getAndIncrementSequence() (uint64, error) {
	sequence, err := hc.sequence.value()
	if err != nil {
		return 0, err
	}
	hc.sequence.increment()
	return sequence, nil
}

// maskedNonce creates a copy of the nonce that is masked with the sequence
// number.
func (hc *S2AHalfConnection) maskedNonce(sequence uint64) []byte {
	const uint64Size = 8
	nonce := make([]byte, len(hc.nonce))
	copy(nonce, hc.nonce)
	for i := 0; i < uint64Size; i++ {
		nonce[nonceSize-uint64Size+i] ^= byte(sequence >> uint64(56-uint64Size*i))
	}
	return nonce
}

// deriveSecret implements the Derive-Secret function, as specified in
// https://tools.ietf.org/html/rfc8446#section-7.1.
func (hc *S2AHalfConnection) deriveSecret(secret, label []byte, length int) ([]byte, error) {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(label)
	})
	// Append an empty `Context` field to the label, as specified in the RFC.
	// The half connection does not use the `Context` field.
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(""))
	})
	hkdfLabelBytes, err := hkdfLabel.Bytes()
	if err != nil {
		return nil, fmt.Errorf("deriveSecret failed: %v", err)
	}
	return hc.expander.expand(hc.h, secret, hkdfLabelBytes, length)
}
