package crypter

import (
	"math"
	"testing"
)

func TestCounterInc(t *testing.T) {
	for _, tc := range []struct {
		desc                     string
		counter, expectedCounter uint64
		overflow                 bool
	}{
		{
			desc:            "basic 1",
			counter:         0,
			expectedCounter: 1,
		},
		{
			desc:            "basic 2",
			counter:         123,
			expectedCounter: 124,
		},
		{
			desc:            "almost overflow",
			counter:         math.MaxUint64 - 1,
			expectedCounter: math.MaxUint64,
		},
		{
			desc:     "max overflow",
			counter:  math.MaxUint64,
			overflow: true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			c := counter{value: tc.counter}
			c.inc()
			val, err := c.val()
			if tc.overflow {
				if err == nil {
					t.Errorf("counter starting with %v, val() expected error, received none", tc.counter)
				}
			} else {
				if err != nil {
					t.Errorf("counter starting with %v, val() returned error: %v", tc.counter, err)
				}
				if val != tc.expectedCounter {
					t.Errorf("counter starting with %v, val() = %v, want %v", tc.counter, val, tc.expectedCounter)
				}
			}

			if tc.overflow != c.hasOverflowed {
				t.Errorf("counter starting with %v, c.hasOverflowed = %v, want %v", tc.counter, c.hasOverflowed, tc.overflow)
			}
		})
	}
}

func TestCounterReset(t *testing.T) {
	for _, tc := range []struct {
		desc          string
		counter       uint64
		hasOverflowed bool
	}{
		{
			desc:          "non-zero no overflow",
			counter:       1,
			hasOverflowed: false,
		},
		{
			desc:          "zero no overflow",
			counter:       0,
			hasOverflowed: false,
		},
		{
			desc:          "non-zero has overflow",
			counter:       1,
			hasOverflowed: true,
		},
		{
			desc:          "zero has overflow",
			counter:       0,
			hasOverflowed: true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			c := counter{tc.counter, tc.hasOverflowed}
			// Check that resetting the counter works as expected.
			c.reset()
			if c.value != 0 {
				t.Errorf("counter with value %v, c.value = %v, want 0", tc.counter, c.value)
			}
			if c.hasOverflowed != false {
				t.Errorf("counter with value %v, c.hasOverflowed = %v, want false", tc.counter, c.hasOverflowed)
			}
		})
	}
}
