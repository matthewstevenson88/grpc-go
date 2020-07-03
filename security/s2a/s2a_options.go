package s2a

import (
	"errors"

	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

type TLSVersion int32

const (
	TLSVersion12 TLSVersion = 0
	TLSVersion13 TLSVersion = 1
)

type Identity interface {
	Name() string
	Clone() Identity
}

type SpiffeID struct {
	spiffeID string
}

func (s *SpiffeID) Name() string { return s.spiffeID }

func (s *SpiffeID) Clone() Identity {
	c := *s
	return &c
}

func NewSpiffeID(spiffeID string) *SpiffeID {
	return &SpiffeID{spiffeID: spiffeID}
}

type Hostname struct {
	hostname string
}

func (h *Hostname) Name() string { return h.hostname }

func (h *Hostname) Clone() Identity {
	c := *h
	return &c
}

func NewHostname(hostname string) *Hostname {
	return &Hostname{hostname: hostname}
}

// ClientOptions contains the client-side options used to establish a secure
// channel using the S2A handshaker service.
type ClientOptions struct {
	// MinTLSVersion specifies the min TLS version supported by the client.
	MinTLSVersion TLSVersion
	// MaxTLSVersion specifies the max TLS version supported by the client.
	MaxTLSVersion TLSVersion
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
	// MinTLSVersion specifies the min TLS version supported by the server.
	MinTLSVersion TLSVersion
	// MaxTLSVersion specifies the max TLS version supported by the server.
	MaxTLSVersion TLSVersion
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

func toProtoTLSVersion(tlsVersion TLSVersion) (s2apb.TLSVersion, error) {
	switch tlsVersion {
	case TLSVersion12:
		return s2apb.TLSVersion_TLS1_2, nil
	case TLSVersion13:
		return s2apb.TLSVersion_TLS1_3, nil
	default:
		return 0, errors.New("unrecognized tls version")
	}
}
