package crypter

import (
	"math"
	"testing"
)

type counterTest struct {
	desc                     string
	counter, expectedCounter uint64
	overflow                 bool
}

func TestCounterInc(t *testing.T) {
	for _, test := range []counterTest{
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
			desc:            "max overflow",
			counter:         math.MaxUint64 - 1,
			expectedCounter: math.MaxUint64,
		},
		{
			desc:     "max overflow",
			counter:  math.MaxUint64,
			overflow: true,
		},
	} {
		// Make first getAndIncrement call. This should return the same value
		// which was given.
		c := newCounter(test.counter)
		value, err := c.getAndIncrement()
		if err != nil {
			t.Errorf("counter(%v).getAndIncrement() returned error: %v", test.counter, err)
		}
		if value != test.counter {
			t.Errorf("counter(%v).getAndIncrement() = %v, want %v", test.counter, value, test.counter)
		}
		if test.overflow {
			if !c.hasOverflowed {
				t.Errorf("counter(%v).getAndIncrement() did not set hasOverflowed flag", test.counter)
			}
		} else {
			if c.hasOverflowed {
				t.Errorf("counter(%v).getAndIncrement() unexpectedly set hasOverflowed flag", test.counter)
			}
		}

		// Make second getAndIncrement call. This should verify that the first
		// getAndIncrement call succeeded in incrementing the value.
		value, err = c.getAndIncrement()
		if test.overflow {
			if err == nil {
				t.Errorf("counter(%v).getAndIncrement() expected error, received none", test.counter)
			}
			if !c.hasOverflowed {
				t.Errorf("counter(%v).getAndIncrement() did not set hasOverflowed flag", test.counter)
			}
		} else {
			if err != nil {
				t.Errorf("counter(%v).getAndIncrement() returned error: %v", test.counter, err)
			}
			if value != test.expectedCounter {
				t.Errorf("counter(%v).getAndIncrement() = %v, want %v", test.counter, value, test.expectedCounter)
			}
		}
	}
}

func TestCounterReset(t *testing.T) {
	for _, test := range []counterTest{
		{
			desc:    "basic reset",
			counter: 1,
		},
		{
			desc:    "reset after overflow",
			counter: math.MaxUint64,
		},
	} {
		c := newCounter(test.counter)
		_, err := c.getAndIncrement()
		if err != nil {
			t.Errorf("counter(%v).getAndIncrement() returned error: %v", test.counter, err)
		}

		// Check that resetting the counter works as expected.
		c.reset()
		value, err := c.getAndIncrement()
		if err != nil {
			t.Errorf("counter returned an error after resetting: %v", err)
		}
		if value != 0 {
			t.Errorf("counter(%v).reset().getAndIncrement() = %v, expected 0", test.counter, err)
		}
	}
}
