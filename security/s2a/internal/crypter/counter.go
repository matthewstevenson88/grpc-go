package crypter

import "errors"

// counter is a 64-bit counter.
type counter struct {
	val           uint64
	hasOverflowed bool
}

// newCounter creates a new counter with the initial value set to val.
func newCounter(val uint64) counter {
	return counter{val: val}
}

// value returns the current value of the counter.
func (c *counter) value() (uint64, error) {
	if c.hasOverflowed {
		return 0, errors.New("counter has overflowed")
	}
	return c.val, nil
}

// increment increments the counter and checks for overflow.
func (c *counter) increment() {
	// If the counter is already invalid due to overflow, there is no need to
	// increase it. We check for the hasOverflowed flag in the call to value().
	if c.hasOverflowed {
		return
	}
	c.val++
	if c.val == 0 {
		c.hasOverflowed = true
	}
}

// reset sets the counter value to zero and sets the hasOverflowed flag to
// false.
func (c *counter) reset() {
	c.val = 0
	c.hasOverflowed = false
}
