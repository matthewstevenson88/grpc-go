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

func TestCounterInc(t *testing.T) {
	for _, test := range []struct {
		desc          string
		counter, want []byte
		overflow      bool
	}{
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
		c := counterFromValue(test.counter)
		c.inc()
		value, err := c.val()
		if test.overflow {
			if err == nil {
				t.Errorf("counter(%v).val() expected error, received none", test.counter)
			}
		} else {
			if err != nil {
				t.Errorf("counter(%v).val() returned error: %v", test.counter, err)
			}
			if !bytes.Equal(value, test.want) {
				t.Errorf("counter(%v).val() = %v, want %v", test.counter, value, test.want)
			}
			if c.hasOverflowed {
				t.Errorf("counter(%v).val() unexpectedly set hasOverflowed flag", test.counter)
			}
		}

		// Check that resetting the counter works as expected.
		c.reset()
		value, err = c.val()
		if err != nil {
			t.Errorf("counter returned an error after resetting: %v", err)
		}
		if binary.LittleEndian.Uint64(value) != 0 {
			t.Errorf("counter(%v).reset.val() = %v, expected 0", test.counter, err)
		}
	}
}
