package s2a

import (
	"errors"

	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

type Identity interface {
	Name() string
}

type SpiffeID struct {
	spiffeID string
}

func (s *SpiffeID) Name() string { return s.spiffeID }

func NewSpiffeID(spiffeID string) *SpiffeID {
	return &SpiffeID{spiffeID: spiffeID}
}

type Hostname struct {
	hostname string
}

func (h *Hostname) Name() string { return h.hostname }

func NewHostname(hostname string) *Hostname {
	return &Hostname{hostname: hostname}
}

// ClientOptions contains the client-side options used to establish a secure
// channel using the S2A handshaker service.
type ClientOptions struct {
	// TargetIdentities contains a list of allowed server identities. One of the
	// target identities should match the peer identity in the handshake
	// result; otherwise, the handshake fails.
	TargetIdentities []Identity
	// LocalIdentity is the local identity of the client application. If none is
	// provided, then the S2A will choose the default identity.
	LocalIdentity Identity
	// HandshakerServiceAddress is the address of the S2A handshaker service.
	HandshakerServiceAddress string
}

// ServerOptions contains the server-side options used to establish a secure
// channel using the S2A handshaker service.
type ServerOptions struct {
	// LocalIdentities is the list of local identities that may be assumed by
	// the server. If no local identity is specified, then the S2A chooses a
	// default local identity.
	LocalIdentities []Identity
	// HandshakerServiceAddress is the address of the S2A handshaker service.
	HandshakerServiceAddress string
}

func toProtoIdentity(identity Identity) (*s2apb.Identity, error) {
	switch id := identity.(type) {
	case *SpiffeID:
		return &s2apb.Identity{IdentityOneof: &s2apb.Identity_SpiffeId{SpiffeId: id.Name()}}, nil
	case *Hostname:
		return &s2apb.Identity{IdentityOneof: &s2apb.Identity_Hostname{Hostname: id.Name()}}, nil
	default:
		return nil, errors.New("unrecognized identity type")
	}
}
