package crypter

import "errors"

const counterLen = 12

// counter is a 96-bit, little-endian counter.
type counter struct {
	value   [counterLen]byte
	invalid bool
}

func newCounter() counter {
	return counter{}
}

// val returns the current value of the counter as a byte slice.
func (c *counter) val() ([]byte, error) {
	if c.invalid {
		return nil, errors.New("invalid counter, possibly due to overflow")
	}
	return c.value[:], nil
}

// inc increments the counter and checks for overflow.
func (c *counter) inc() {
	// If the counter is already invalid, there is no need to increase it. We
	// check for the invalid flag in the call to val().
	if c.invalid {
		return
	}
	i := 0
	for ; i < counterLen; i++ {
		c.value[i]++
		if c.value[i] != 0 {
			break
		}
	}
	if i == counterLen {
		c.invalid = true
	}
}
