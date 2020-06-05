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

// val returns the current value of the counter as a byte slice.
func (c *counter) val() ([]byte, error) {
	if c.hasOverflowed {
		return nil, errors.New("invalid counter due to overflow")
	}
	buf := make([]byte, counterLen)
	binary.LittleEndian.PutUint64(buf, c.value)
	return buf, nil
}

// inc increments the counter and checks for overflow.
func (c *counter) inc() {
	// If the counter is already invalid due to overflow, there is no need to
	// increase it. We check for the hasOverflowed flag in the call to val().
	if c.hasOverflowed {
		return
	}
	c.value++
	if c.value == 0 {
		c.hasOverflowed = true
	}
}

// reset sets the counter value to zero and resets the hasOverflowed flag.
func (c *counter) reset() {
	c.value = 0
	c.hasOverflowed = false
}
