package crypter

import (
	"errors"
)

// counter is a 64-bit counter.
type counter struct {
	value         uint64
	hasOverflowed bool
}

func newCounter(value uint64) counter {
	return counter{value: value}
}

// getAndIncrement returns the current value of the counter and increments it.
func (c *counter) getAndIncrement() (uint64, error) {
	if c.hasOverflowed {
		return 0, errors.New("counter has overflowed")
	}
	val := c.value
	c.value++
	if c.value == 0 {
		c.hasOverflowed = true
	}
	return val, nil
}

// reset sets the counter value to zero and sets hasOverflowed to false.
func (c *counter) reset() {
	c.value = 0
	c.hasOverflowed = false
}
