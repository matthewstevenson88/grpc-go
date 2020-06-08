package crypter

import "errors"

// counter is a 64-bit counter.
type counter struct {
	value         uint64
	hasOverflowed bool
}

func newCounter() counter {
	return counter{}
}

// val returns the current value of the counter.
func (c *counter) val() (uint64, error) {
	if c.hasOverflowed {
		return 0, errors.New("counter has overflowed")
	}
	return c.value, nil
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

// reset sets the counter value to zero and sets the hasOverflowed flag to
// false.
func (c *counter) reset() {
	c.value = 0
	c.hasOverflowed = false
}
