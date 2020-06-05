package crypter

import (
	"bytes"
	"google.golang.org/grpc/security/s2a/internal/crypter/testutil"
	"testing"
)

// counterFromValue creates a new counter given an initial value.
func counterFromValue(value []byte) (c counter) {
	copy(c.value[:], value)
	return
}

func TestCounterInc(t *testing.T) {
	for _, test := range []struct {
		desc          string
		counter, want []byte
		overflow      bool
	}{
		{
			desc:    "basic 1",
			counter: testutil.Dehex("000000000000000000000000"),
			want:    testutil.Dehex("010000000000000000000000"),
		},
		{
			desc:    "basic 2",
			counter: testutil.Dehex("000000000000000000000080"),
			want:    testutil.Dehex("010000000000000000000080"),
		},
		{
			desc:    "basic 3",
			counter: testutil.Dehex("42ff00000000000000000000"),
			want:    testutil.Dehex("43ff00000000000000000000"),
		},
		{
			desc:    "hex overflow 1",
			counter: testutil.Dehex("ff0000000000000000000000"),
			want:    testutil.Dehex("000100000000000000000000"),
		},
		{
			desc:    "hex overflow 2",
			counter: testutil.Dehex("ffffffff0000000000000000"),
			want:    testutil.Dehex("000000000100000000000000"),
		},
		{
			desc:    "hex overflow 3",
			counter: testutil.Dehex("ffffffff0000000000000080"),
			want:    testutil.Dehex("000000000100000000000080"),
		},
		{
			desc:     "max overflow",
			counter:  testutil.Dehex("ffffffffffffffffffffffff"),
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
			if c.invalid {
				t.Errorf("counter(%v).val() unexpectedly set invalid flag", test.counter)
			}
		}
	}
}
