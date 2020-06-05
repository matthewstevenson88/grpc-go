package crypter

import (
	"encoding/binary"
	"errors"
)

// counterLen is the byte length of the counter.
const counterLen = 8

// counter is a 64-bit, little-endian counter.
type counter struct {
	value         uint64
	hasOverflowed bool
}

func newCounter(value uint64) counter {
	return counter{value: value}
}

// getAndIncrement returns the current value of the counter as a byte slice,
// and increments the underlying value.
func (c *counter) getAndIncrement() ([]byte, error) {
	if c.hasOverflowed {
		return nil, errors.New("invalid counter due to overflow")
	}
	buf := make([]byte, counterLen)
	binary.LittleEndian.PutUint64(buf, c.value)
	c.value++
	if c.value == 0 {
		c.hasOverflowed = true
	}
	return buf, nil
}

// reset sets the counter value to zero and sets hasOverflowed to false.
func (c *counter) reset() {
	c.value = 0
	c.hasOverflowed = false
}
