package crypter

import (
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	s2a_proto "google.golang.org/grpc/security/s2a/internal"
	"hash"
	"sync"
)

const (
	tls13Key    = "tls13 key"
	tls13Nonce  = "tls13 iv"
	tls13Update = "tls13 upd"
)

type S2AHalfConnection struct {
	h             func() hash.Hash
	aeadCrypter   s2aAeadCrypter
	expander      hkdfExpander
	seqCounter    counter
	mutex         sync.Mutex
	trafficSecret []byte
	nonce         []byte
}

func NewHalfConn(ciphersuite s2a_proto.Ciphersuite, trafficSecret []byte) (S2AHalfConnection, error) {
	cs := NewCiphersuite(ciphersuite)
	if cs.trafficSecretSize() != len(trafficSecret) {
		return S2AHalfConnection{}, fmt.Errorf("supplied traffic secret must be %v bytes, given: %v", cs.trafficSecretSize(), trafficSecret)
	}

	hc := S2AHalfConnection{h: cs.hashFunction(), expander: &defaultHKDFExpander{}, seqCounter: newCounter()}
	key, err := hc.deriveSecret(hc.h, trafficSecret, []byte(tls13Key))
	if err != nil {
		return S2AHalfConnection{}, fmt.Errorf("hc.deriveSecret(h, %v, %v) failed with error: %v", trafficSecret, tls13Key, err)
	}
	hc.aeadCrypter, err = cs.aeadCrypter(key)
	if err != nil {
		return S2AHalfConnection{}, fmt.Errorf("cs.aeadCrypter(%v) failed with error: %v", key, err)
	}
	hc.nonce, err = hc.deriveSecret(hc.h, trafficSecret, []byte(tls13Nonce))
	if err != nil {
		return S2AHalfConnection{}, fmt.Errorf("hc.deriveSecret(h, %v, %v) failed with error: %v", trafficSecret, tls13Nonce, err)
	}
	return hc, nil
}

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

func (hc *S2AHalfConnection) UpdateKey() error {
	var err error
	hc.trafficSecret, err = hc.deriveSecret(hc.h, hc.trafficSecret, []byte(tls13Update))
	if err != nil {
		return fmt.Errorf("hc.deriveSecret(h, %v, %v) failed with error: %v", hc.trafficSecret, tls13Update, err)
	}
	key, err := hc.deriveSecret(hc.h, hc.trafficSecret, []byte(tls13Key))
	if err != nil {
		return fmt.Errorf("hc.deriveSecret(h, %v, %v) failed with error: %v", hc.trafficSecret, tls13Key, err)
	}
	err = hc.aeadCrypter.updateKey(key)
	if err != nil {
		return fmt.Errorf("hc.aeadCrypter.updateKey(%v) failed with error: %v", key, err)
	}
	hc.nonce, err = hc.deriveSecret(hc.h, hc.trafficSecret, []byte(tls13Nonce))
	if err != nil {
		return fmt.Errorf("hc.deriveSecret(h, %v, %v) failed with error: %v", hc.trafficSecret, tls13Nonce, err)
	}
	hc.seqCounter.reset()
	return nil
}

func (hc *S2AHalfConnection) getAndIncrementSequence() (uint64, error) {
	sequence, err := hc.seqCounter.val()
	if err != nil {
		return 0, err
	}
	hc.seqCounter.inc()
	return sequence, nil
}

func (hc *S2AHalfConnection) maskedNonce(sequence uint64) []byte {
	for i := 0; i < uint64Size; i++ {
		hc.nonce[nonceSize-8+i] ^= sequence >> (56 - 8*i)
	}
	return hc.nonce
}

// deriveSecret implements Derive-Secret specified in
// https://tools.ietf.org/html/rfc8446#section-7.1.
func (hc *S2AHalfConnection) deriveSecret(h func() hash.Hash, secret, label []byte) ([]byte, error) {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(h().Size()))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(label)
	})
	hkdfLabelBytes, err := hkdfLabel.Bytes()
	if err != nil {
		return nil, fmt.Errorf("deriveSecret failed with error: %v", err)
	}
	return hc.expander.expand(h, secret, hkdfLabelBytes)
}
