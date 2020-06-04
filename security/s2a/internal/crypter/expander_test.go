package crypter

import (
	"bytes"
	"crypto/sha256"
	"google.golang.org/grpc/security/s2a/internal/crypter/testutil"
	"testing"
)

func TestExpand(t *testing.T) {
	// The following test vectors were taken from
	// https://tools.ietf.org/html/rfc5869. Note have vectors have
	// been slightly modified to test our specific implementation. In
	// particular, the output has been shortened since we our implementation
	// doesn't take `length` as a parameter and the output length is determined
	// by the hash. Also note that `prk` and `okm` mentioned in the RFC have
	// been renamed to `secret` and `out`.
	for _, tc := range []struct {
		desc              string
		secret, info, out []byte
		length            int
	}{
		{
			desc:   "sha256 basic",
			secret: testutil.Dehex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
			info:   testutil.Dehex("f0f1f2f3f4f5f6f7f8f9"),
			out:    testutil.Dehex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"),
		},
		{
			desc:   "sha256 longer input/output",
			secret: testutil.Dehex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),
			info:   testutil.Dehex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
			out:    testutil.Dehex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"),
		},
		{
			desc:   "sha256 zero length info",
			secret: testutil.Dehex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
			out:    testutil.Dehex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"),
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			expander := newDefaultHKDFExpander()
			got, err := expander.expand(sha256.New, tc.secret, tc.info)
			if err != nil {
				t.Errorf("expand failed with error: %v", err)
			}
			if !bytes.Equal(got, tc.out) {
				t.Errorf("expand(sha256.New, %v, %v) = %v, want %v.", tc.secret, tc.info, got, tc.out)
			}
		})
	}
}
