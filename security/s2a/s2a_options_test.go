package s2a

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

func TestToProtoIdentity(t *testing.T) {
	for _, tc := range []struct {
		identity    Identity
		outIdentity *s2apb.Identity
	}{
		{
			identity:    NewSpiffeID("test_spiffe_id"),
			outIdentity: &s2apb.Identity{IdentityOneof: &s2apb.Identity_SpiffeId{SpiffeId: "test_spiffe_id"}},
		},
		{
			identity:    NewHostname("test_hostname"),
			outIdentity: &s2apb.Identity{IdentityOneof: &s2apb.Identity_Hostname{Hostname: "test_hostname"}},
		},
	} {
		t.Run(tc.outIdentity.String(), func(t *testing.T) {
			protoSpiffeID, err := toProtoIdentity(tc.identity)
			if err != nil {
				t.Errorf("toProtoIdentity(%v) failed: %v", tc.identity, err)
			}
			if got, want := protoSpiffeID, tc.outIdentity; !cmp.Equal(got, want) {
				t.Errorf("toProtoIdentity(%v) = %v, want %v", tc.outIdentity, got, want)
			}
		})
	}
}

func TestToProtoTLSVersion(t *testing.T) {
	for _, tc := range []struct {
		tlsVersion    TLSVersion
		outTLSVersion s2apb.TLSVersion
	}{
		{
			tlsVersion:    TLSVersion12,
			outTLSVersion: s2apb.TLSVersion_TLS1_2,
		},
		{
			tlsVersion:    TLSVersion13,
			outTLSVersion: s2apb.TLSVersion_TLS1_3,
		},
	} {
		t.Run(tc.outTLSVersion.String(), func(t *testing.T) {
			protoTLSVersion, err := toProtoTLSVersion(tc.tlsVersion)
			if err != nil {
				t.Errorf("toProtoTLSVersion(%v) failed: %v", tc.tlsVersion, err)
			}
			if got, want := protoTLSVersion, tc.outTLSVersion; got != want {
				t.Errorf("toProtoTLSVersion(%v) = %v, want %v", tc.outTLSVersion, got, want)
			}
		})
	}
}
