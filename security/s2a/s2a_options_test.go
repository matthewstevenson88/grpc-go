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
			identity: NewSpiffeID("test_spiffe_id"),
			outIdentity: &s2apb.Identity{
				IdentityOneof: &s2apb.Identity_SpiffeId{SpiffeId: "test_spiffe_id"},
			},
		},
		{
			identity: NewHostname("test_hostname"),
			outIdentity: &s2apb.Identity{
				IdentityOneof: &s2apb.Identity_Hostname{Hostname: "test_hostname"},
			},
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
