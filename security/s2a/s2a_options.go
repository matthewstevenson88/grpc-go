package s2a

import (
	"errors"

	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

// Identity is the interface for S2A identities.
type Identity interface {
	// Name returns the name of the identity.
	Name() string
}

type spiffeID struct {
	spiffeID string
}

func (s *spiffeID) Name() string { return s.spiffeID }

func NewSpiffeID(id string) Identity {
	return &spiffeID{spiffeID: id}
}

type hostname struct {
	hostname string
}

func (h *hostname) Name() string { return h.hostname }

func NewHostname(name string) Identity {
	return &hostname{hostname: name}
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

// DefaultClientOptions returns the default client options.
func DefaultClientOptions(handshakerAddress string) *ClientOptions {
	return &ClientOptions{HandshakerServiceAddress: handshakerAddress}
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

// DefaultServerOptions returns the default server options.
func DefaultServerOptions(handshakerAddress string) *ServerOptions {
	return &ServerOptions{HandshakerServiceAddress: handshakerAddress}
}

func toProtoIdentity(identity Identity) (*s2apb.Identity, error) {
	switch id := identity.(type) {
	case *spiffeID:
		return &s2apb.Identity{IdentityOneof: &s2apb.Identity_SpiffeId{SpiffeId: id.Name()}}, nil
	case *hostname:
		return &s2apb.Identity{IdentityOneof: &s2apb.Identity_Hostname{Hostname: id.Name()}}, nil
	default:
		return nil, errors.New("unrecognized identity type")
	}
}
