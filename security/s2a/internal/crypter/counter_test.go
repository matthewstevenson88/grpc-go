package crypter

import (
	"bytes"
	"encoding/binary"
	"google.golang.org/grpc/security/s2a/internal/crypter/testutil"
	"testing"
)

// counterFromValue creates a new counter given an initial value.
func counterFromValue(value []byte) (c counter) {
	return newCounter(binary.LittleEndian.Uint64(value))
}

type counterTest struct {
	desc          string
	counter, want []byte
	overflow      bool
}

func TestCounterInc(t *testing.T) {
	for _, test := range []counterTest{
		{
			desc:    "basic 1",
			counter: testutil.Dehex("0000000000000000"),
			want:    testutil.Dehex("0100000000000000"),
		},
		{
			desc:    "basic 2",
			counter: testutil.Dehex("0000000000000080"),
			want:    testutil.Dehex("0100000000000080"),
		},
		{
			desc:    "basic 3",
			counter: testutil.Dehex("42ff000000000000"),
			want:    testutil.Dehex("43ff000000000000"),
		},
		{
			desc:    "hex overflow 1",
			counter: testutil.Dehex("ff00000000000000"),
			want:    testutil.Dehex("0001000000000000"),
		},
		{
			desc:    "hex overflow 2",
			counter: testutil.Dehex("ffffffff00000000"),
			want:    testutil.Dehex("0000000001000000"),
		},
		{
			desc:    "hex overflow 3",
			counter: testutil.Dehex("ffffffff00000000"),
			want:    testutil.Dehex("0000000001000000"),
		},
		{
			desc:     "max overflow",
			counter:  testutil.Dehex("ffffffffffffffff"),
			overflow: true,
		},
	} {
		// Test first getAndIncrement call. This should return the same value
		// which was given.
		c := counterFromValue(test.counter)
		value, err := c.getAndIncrement()
		if err != nil {
			t.Errorf("counter(%v).getAndIncrement() returned error: %v", test.counter, err)
		}
		if !bytes.Equal(value, test.counter) {
			t.Errorf("counter(%v).getAndIncrement() = %v, want %v", test.counter, value, test.counter)
		}

		// Test second getAndIncrement call. This should verify that the first
		// getAndIncrement call succeeded in incrementing the value.
		value, err = c.getAndIncrement()
		if test.overflow {
			if err == nil {
				t.Errorf("counter(%v).getAndIncrement() expected error, received none", test.counter)
			}
		} else {
			if err != nil {
				t.Errorf("counter(%v).getAndIncrement() returned error: %v", test.counter, err)
			}
			if !bytes.Equal(value, test.want) {
				t.Errorf("counter(%v).getAndIncrement() = %v, want %v", test.counter, value, test.want)
			}
			if c.hasOverflowed {
				t.Errorf("counter(%v).getAndIncrement() unexpectedly set hasOverflowed flag", test.counter)
			}
		}
	}
}

func TestCounterReset(t *testing.T) {
	for _, test := range []counterTest{
		{
			desc:    "basic reset",
			counter: testutil.Dehex("0100000000000000"),
		},
		{
			desc:    "reset after overflow",
			counter: testutil.Dehex("ffffffffffffffff"),
		},
	} {
		c := counterFromValue(test.counter)
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
		if binary.LittleEndian.Uint64(value) != 0 {
			t.Errorf("counter(%v).reset.getAndIncrement() = %v, expected 0", test.counter, err)
		}
	}
}
