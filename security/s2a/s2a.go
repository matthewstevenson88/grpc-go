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

// s2aTransportCreds are the credentials required for establishing a secure
// connection using the S2A handshaker service. It implements the
// credentials.TransportCredentials interface.
type s2aTransportCreds struct {
	info          *credentials.ProtocolInfo
	minTLSVersion s2apb.TLSVersion
	maxTLSVersion s2apb.TLSVersion
	// tlsCiphersuites contains the ciphersuites used in the S2A connection.
	// Note that these are currently unconfigurable.
	tlsCiphersuites []s2apb.Ciphersuite
	// localIdentity should only be used by the client.
	localIdentity *s2apb.Identity
	// localIdentities should only be used by the server.
	localIdentities []*s2apb.Identity
	// targetIdentities should only be used by the client.
	targetIdentities []*s2apb.Identity
	isClient         bool
	hsAddr           string
}

// NewClientCreds returns a client-side transport credentials object that uses
// the S2A handshaker service to establish a secure connection with a server.
func NewClientCreds(opts *ClientOptions) (credentials.TransportCredentials, error) {
	if opts == nil {
		return nil, errors.New("nil client options")
	}
	var targetIdentities []*s2apb.Identity
	for _, targetIdentity := range opts.TargetIdentities {
		protoTargetIdentity, err := toProtoIdentity(targetIdentity)
		if err != nil {
			return nil, err
		}
		targetIdentities = append(targetIdentities, protoTargetIdentity)
	}
	localIdentity, err := toProtoIdentity(opts.LocalIdentity)
	if err != nil {
		return nil, err
	}
	return &s2aTransportCreds{
		info: &credentials.ProtocolInfo{
			SecurityProtocol: s2aSecurityProtocol,
		},
		minTLSVersion: s2apb.TLSVersion_TLS1_3,
		maxTLSVersion: s2apb.TLSVersion_TLS1_3,
		tlsCiphersuites: []s2apb.Ciphersuite{
			s2apb.Ciphersuite_AES_128_GCM_SHA256,
			s2apb.Ciphersuite_AES_256_GCM_SHA384,
			s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
		},
		localIdentity:    localIdentity,
		targetIdentities: targetIdentities,
		isClient:         true,
		hsAddr:           opts.HandshakerServiceAddress,
	}, nil
}

// NewServerCreds returns a server-side transport credentials object that uses
// the S2A handshaker service to establish a secure connection with a client.
func NewServerCreds(opts *ServerOptions) (credentials.TransportCredentials, error) {
	if opts == nil {
		return nil, errors.New("nil server options")
	}
	var localIdentities []*s2apb.Identity
	for _, localIdentity := range opts.LocalIdentities {
		protoLocalIdentity, err := toProtoIdentity(localIdentity)
		if err != nil {
			return nil, err
		}
		localIdentities = append(localIdentities, protoLocalIdentity)
	}
	return &s2aTransportCreds{
		info: &credentials.ProtocolInfo{
			SecurityProtocol: s2aSecurityProtocol,
		},
		minTLSVersion: s2apb.TLSVersion_TLS1_3,
		maxTLSVersion: s2apb.TLSVersion_TLS1_3,
		tlsCiphersuites: []s2apb.Ciphersuite{
			s2apb.Ciphersuite_AES_128_GCM_SHA256,
			s2apb.Ciphersuite_AES_256_GCM_SHA384,
			s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
		},
		localIdentities: localIdentities,
		isClient:        false,
		hsAddr:          opts.HandshakerServiceAddress,
	}, nil
}

// ClientHandshake performs a client-side TLS handshake using the S2A handshaker
// service.
func (c *s2aTransportCreds) ClientHandshake(ctx context.Context, serverAddr string, rawConn net.Conn) (_ net.Conn, _ credentials.AuthInfo, err error) {
	if !c.isClient {
		return nil, nil, errors.New("client handshake called using server transport credentials")
	}

	// Connect to the S2A handshaker service.
	hsConn, err := service.Dial(c.hsAddr)
	if err != nil {
		return nil, nil, err
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	defer cancel()

	opts := &handshaker.ClientHandshakerOptions{
		MinTLSVersion:    c.minTLSVersion,
		MaxTLSVersion:    c.maxTLSVersion,
		TLSCiphersuites:  c.tlsCiphersuites,
		TargetIdentities: c.targetIdentities,
		LocalIdentity:    c.localIdentity,
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

	secConn, authInfo, err := chs.ClientHandshake(context.Background())
	if err != nil {
		return nil, nil, err
	}
	return secConn, authInfo, nil
}

// ServerHandshake performs a server-side TLS handshake using the S2A handshaker
// service.
func (c *s2aTransportCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if c.isClient {
		return nil, nil, errors.New("server handshake called using client transport credentials")
	}

	// Connect to the S2A handshaker service.
	hsConn, err := service.Dial(c.hsAddr)
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	opts := &handshaker.ServerHandshakerOptions{
		MinTLSVersion:   c.minTLSVersion,
		MaxTLSVersion:   c.maxTLSVersion,
		TLSCiphersuites: c.tlsCiphersuites,
		LocalIdentities: c.localIdentities,
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

	secConn, authInfo, err := shs.ServerHandshake(context.Background())
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
	var localIdentity *s2apb.Identity
	if c.localIdentity != nil {
		v := *c.localIdentity
		localIdentity = &v
	}
	var localIdentities []*s2apb.Identity
	if c.localIdentities != nil {
		localIdentities = make([]*s2apb.Identity, len(c.localIdentities))
		for i, localIdentity := range c.localIdentities {
			v := *localIdentity
			localIdentities[i] = &v
		}
	}
	var targetIdentities []*s2apb.Identity
	if c.targetIdentities != nil {
		targetIdentities = make([]*s2apb.Identity, len(c.targetIdentities))
		for i, targetIdentity := range c.targetIdentities {
			v := *targetIdentity
			targetIdentities[i] = &v
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
		isClient:         c.isClient,
		hsAddr:           c.hsAddr,
	}
}

func (c *s2aTransportCreds) OverrideServerName(serverNameOverride string) error {
	c.info.ServerName = serverNameOverride
	return nil
}
