/*
 *
 * Copyright 2020 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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
