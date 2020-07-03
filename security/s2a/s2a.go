package s2a

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/security/s2a/internal/handshaker"
	"google.golang.org/grpc/security/s2a/internal/handshaker/service"
	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

const (
	s2aSecurityProtocol = "s2a"
	// defaultTimeout specifies the default server handshake timeout.
	defaultTimeout = 30.0 * time.Second
)

type TLSVersion int32

const (
	TLSVersion12 TLSVersion = 0
	TLSVersion13 TLSVersion = 1
)

type Ciphersuite int32

const (
	CiphersuiteAES128GCMSHA256        Ciphersuite = 0
	CiphersuiteAES256GCMSHA384        Ciphersuite = 1
	CiphersuiteCHACHA20POLY1305SHA256 Ciphersuite = 2
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

type Hostname struct {
	hostname string
}

func (h *Hostname) Name() string { return h.hostname }

func (h *Hostname) Clone() Identity {
	c := *h
	return &c
}

// ClientOptions contains the client-side options of an S2A channel. These
// options will be passed to the underlying S2A handshaker.
type ClientOptions struct {
	// MinTLSVersion specifies the min TLS version supported by the client.
	MinTLSVersion TLSVersion
	// MaxTLSVersion specifies the max TLS version supported by the client.
	MaxTLSVersion TLSVersion
	// TLSCiphersuites is the ordered list of ciphersuites supported by the
	// client.
	TLSCiphersuites []Ciphersuite
	// TargetIdentities contains a list of allowed server identities. One of the
	// target identities should match the peer identity in the handshake
	// result; otherwise, the handshake fails.
	TargetIdentities []Identity
	// LocalIdentity is the local identity of the client application. If none is
	// provided, then the S2A will choose the default identity.
	LocalIdentity Identity
	// HSAddr represents the S2A handshaker gRPC service address to connect to.
	HSAddr string
}

// ServerOptions contains the server-side options of an S2A channel. These
// options will be passed to the underlying S2A handshaker.
type ServerOptions struct {
	// MinTLSVersion specifies the min TLS version supported by the server.
	MinTLSVersion TLSVersion
	// MaxTLSVersion specifies the max TLS version supported by the server.
	MaxTLSVersion TLSVersion
	// TLSCiphersuites is the ordered list of ciphersuites supported by the
	// server.
	TLSCiphersuites []Ciphersuite
	// LocalIdentities is the local identities that may be assumed by the
	// server. If no local identity is specified, then the S2A chooses a default
	// local identity.
	LocalIdentities []Identity
	// HSAddr represents the S2A handshaker gRPC service address to connect to.
	HSAddr string
}

// s2aTransportCreds is the credentials required for authenticating a connection
// using S2A. It implements the credentials.TransportCredentials interface.
type s2aTransportCreds struct {
	info             *credentials.ProtocolInfo
	minTLSVersion    TLSVersion
	maxTLSVersion    TLSVersion
	tlsCiphersuites  []Ciphersuite
	localIdentity    Identity
	localIdentities  []Identity
	targetIdentities []Identity
	hsAddr           string
}

// NewClientCreds returns a client-side S2A TransportCredentials object.
func NewClientCreds(opts *ClientOptions) (credentials.TransportCredentials, error) {
	if opts == nil {
		return nil, errors.New("nil client options")
	}
	return &s2aTransportCreds{
		info: &credentials.ProtocolInfo{
			SecurityProtocol: s2aSecurityProtocol,
		},
		minTLSVersion:    opts.MinTLSVersion,
		maxTLSVersion:    opts.MaxTLSVersion,
		tlsCiphersuites:  opts.TLSCiphersuites,
		localIdentity:    opts.LocalIdentity,
		targetIdentities: opts.TargetIdentities,
		hsAddr:           opts.HSAddr,
	}, nil
}

// NewServerCreds returns a server-side S2A TransportCredentials object.
func NewServerCreds(opts *ServerOptions) (credentials.TransportCredentials, error) {
	if opts == nil {
		return nil, errors.New("nil server options")
	}
	return &s2aTransportCreds{
		info: &credentials.ProtocolInfo{
			SecurityProtocol: s2aSecurityProtocol,
		},
		minTLSVersion:   opts.MinTLSVersion,
		maxTLSVersion:   opts.MaxTLSVersion,
		tlsCiphersuites: opts.TLSCiphersuites,
		localIdentities: opts.LocalIdentities,
		hsAddr:          opts.HSAddr,
	}, nil
}

// ClientHandshake implements the client side handshake protocol.
func (c *s2aTransportCreds) ClientHandshake(ctx context.Context, serverAddr string, rawConn net.Conn) (_ net.Conn, _ credentials.AuthInfo, err error) {
	// Connect to the S2A handshaker service.
	hsConn, err := service.Dial(c.hsAddr)
	if err != nil {
		return nil, nil, err
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	defer cancel()

	var tlsCiphersuites []s2apb.Ciphersuite
	for _, tlsCiphersuite := range c.tlsCiphersuites {
		tlsCiphersuites = append(tlsCiphersuites, s2apb.Ciphersuite(tlsCiphersuite))
	}
	var targetIdentities []*s2apb.Identity
	for _, targetIdentity := range c.targetIdentities {
		protoTargetIdentity, err := toProtoIdentity(targetIdentity)
		if err != nil {
			return nil, nil, err
		}
		targetIdentities = append(targetIdentities, protoTargetIdentity)
	}
	localIdentity, err := toProtoIdentity(c.localIdentity)
	if err != nil {
		return nil, nil, err
	}

	opts := &handshaker.ClientHandshakerOptions{
		MinTLSVersion:    s2apb.TLSVersion(c.minTLSVersion),
		MaxTLSVersion:    s2apb.TLSVersion(c.maxTLSVersion),
		TLSCiphersuites:  tlsCiphersuites,
		TargetIdentities: targetIdentities,
		LocalIdentity:    localIdentity,
		TargetName:       serverAddr,
	}
	chs, err := handshaker.NewClientHandshaker(ctx, hsConn, rawConn, c.hsAddr, opts)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			if closeErr := chs.Close(); closeErr != nil {
				err = fmt.Errorf("%v: close unexpectedly failed: %v", err, closeErr)
			}
		}
	}()

	secConn, authInfo, err := chs.ClientHandshake()
	if err != nil {
		return nil, nil, err
	}
	return secConn, authInfo, nil
}

// ServerHandshake implements the server side S2A handshaker.
func (c *s2aTransportCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	// Connect to the S2A handshaker service.
	hsConn, err := service.Dial(c.hsAddr)
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	var tlsCiphersuites []s2apb.Ciphersuite
	for _, tlsCiphersuite := range c.tlsCiphersuites {
		tlsCiphersuites = append(tlsCiphersuites, s2apb.Ciphersuite(tlsCiphersuite))
	}
	var localIdentities []*s2apb.Identity
	for _, localIdentity := range c.localIdentities {
		protoLocalIdentity, err := toProtoIdentity(localIdentity)
		if err != nil {
			return nil, nil, err
		}
		localIdentities = append(localIdentities, protoLocalIdentity)
	}

	opts := &handshaker.ServerHandshakerOptions{
		MinTLSVersion:   s2apb.TLSVersion(c.minTLSVersion),
		MaxTLSVersion:   s2apb.TLSVersion(c.maxTLSVersion),
		TLSCiphersuites: tlsCiphersuites,
		LocalIdentities: localIdentities,
	}
	shs, err := handshaker.NewServerHandshaker(ctx, hsConn, rawConn, c.hsAddr, opts)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			if closeErr := shs.Close(); closeErr != nil {
				err = fmt.Errorf("%v: close unexpectedly failed: %v", err, closeErr)
			}
		}
	}()

	secConn, authInfo, err := shs.ServerHandshake()
	if err != nil {
		return nil, nil, err
	}
	return secConn, authInfo, nil
}

func (c *s2aTransportCreds) Info() credentials.ProtocolInfo {
	return *c.info
}

func (c *s2aTransportCreds) Clone() credentials.TransportCredentials {
	info := *c.info
	var localIdentity Identity
	if c.localIdentity != nil {
		localIdentity = c.localIdentity.Clone()
	}
	var localIdentities []Identity
	if c.localIdentities != nil {
		localIdentities = make([]Identity, len(c.localIdentities))
		for i, localIdentity := range c.localIdentities {
			localIdentities[i] = localIdentity.Clone()
		}
	}
	var targetIdentities []Identity
	if c.targetIdentities != nil {
		targetIdentities = make([]Identity, len(c.targetIdentities))
		for i, targetIdentity := range c.targetIdentities {
			targetIdentities[i] = targetIdentity.Clone()
		}
	}
	return &s2aTransportCreds{
		info:             &info,
		minTLSVersion:    c.minTLSVersion,
		maxTLSVersion:    c.maxTLSVersion,
		tlsCiphersuites:  c.tlsCiphersuites,
		localIdentity:    localIdentity,
		localIdentities:  localIdentities,
		targetIdentities: targetIdentities,
		hsAddr:           c.hsAddr,
	}
}

func (c *s2aTransportCreds) OverrideServerName(serverNameOverride string) error {
	c.info.ServerName = serverNameOverride
	return nil
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
