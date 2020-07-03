package s2a

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNewClientCreds(t *testing.T) {
	for _, tc := range []struct {
		desc                string
		opts                *ClientOptions
		outMinTLSVersion    TLSVersion
		outMaxTLSVersion    TLSVersion
		outTLSCiphersuites  []Ciphersuite
		outLocalIdentity    Identity
		outTargetIdentities []Identity
		outHSAddr           string
	}{
		{
			desc: "basic 1",
			opts: &ClientOptions{
				MinTLSVersion: TLSVersion12,
				MaxTLSVersion: TLSVersion13,
				TLSCiphersuites: []Ciphersuite{
					CiphersuiteAES128GCMSHA256,
					CiphersuiteAES256GCMSHA384,
					CiphersuiteCHACHA20POLY1305SHA256},
				TargetIdentities: []Identity{
					&SpiffeID{"test spiffe id"},
					&Hostname{"test hostname"},
				},
				LocalIdentity: &Hostname{"test hostname"},
				HSAddr:        "test handshaker address",
			},
			outMinTLSVersion: TLSVersion12,
			outMaxTLSVersion: TLSVersion13,
			outTLSCiphersuites: []Ciphersuite{
				CiphersuiteAES128GCMSHA256,
				CiphersuiteAES256GCMSHA384,
				CiphersuiteCHACHA20POLY1305SHA256},
			outTargetIdentities: []Identity{
				&SpiffeID{"test spiffe id"},
				&Hostname{"test hostname"},
			},
			outLocalIdentity: &Hostname{"test hostname"},
			outHSAddr:        "test handshaker address",
		},
		{
			desc: "basic 2",
			opts: &ClientOptions{
				MinTLSVersion: TLSVersion13,
				MaxTLSVersion: TLSVersion13,
				TLSCiphersuites: []Ciphersuite{
					CiphersuiteAES256GCMSHA384,
					CiphersuiteCHACHA20POLY1305SHA256},
				TargetIdentities: []Identity{
					&Hostname{"test hostname"},
				},
				LocalIdentity: &SpiffeID{"test spiffe id"},
				HSAddr:        "test handshaker address",
			},
			outMinTLSVersion: TLSVersion13,
			outMaxTLSVersion: TLSVersion13,
			outTLSCiphersuites: []Ciphersuite{
				CiphersuiteAES256GCMSHA384,
				CiphersuiteCHACHA20POLY1305SHA256},
			outTargetIdentities: []Identity{
				&Hostname{"test hostname"},
			},
			outLocalIdentity: &SpiffeID{"test spiffe id"},
			outHSAddr:        "test handshaker address",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			c, err := NewClientCreds(tc.opts)
			if err != nil {
				t.Fatalf("NewClientCreds(&ClientOptions{}) failed: %v", err)
			}
			if got, want := c.Info().SecurityProtocol, s2aSecurityProtocol; got != want {
				t.Errorf("c.Info().SecurityProtocol = %v, want %v", got, want)
			}
			s2aCreds, ok := c.(*s2aTransportCreds)
			if !ok {
				t.Error("c.(*s2aTransportCreds) failed")
			}
			if got, want := s2aCreds.minTLSVersion, tc.outMinTLSVersion; got != want {
				t.Errorf("s2aCreds.minTLSVersion = %v, want %v", got, want)
			}
			if got, want := s2aCreds.maxTLSVersion, tc.outMaxTLSVersion; got != want {
				t.Errorf("s2aCreds.maxTLSVersion = %v, want %v", got, want)
			}
			if got, want := s2aCreds.tlsCiphersuites, tc.outTLSCiphersuites; !cmp.Equal(got, want) {
				t.Errorf("s2aCreds.tlsCiphersuites = %v, want %v", got, want)
			}
			if got, want := s2aCreds.targetIdentities, tc.outTargetIdentities; !reflect.DeepEqual(got, want) {
				t.Errorf("s2aCreds.targetIdentities = %v, want %v", got, want)
			}
			if got, want := s2aCreds.localIdentity, tc.outLocalIdentity; !reflect.DeepEqual(got, want) {
				t.Errorf("s2aCreds.localIdentity = %v, want %v", got, want)
			}
			if got, want := s2aCreds.hsAddr, tc.outHSAddr; got != want {
				t.Errorf("s2aCreds.hsAddr = %v, want %v", got, want)
			}
		})
	}
}

func TestNewServerCreds(t *testing.T) {
	for _, tc := range []struct {
		desc               string
		opts               *ServerOptions
		outMinTLSVersion   TLSVersion
		outMaxTLSVersion   TLSVersion
		outTLSCiphersuites []Ciphersuite
		outLocalIdentities []Identity
		outHSAddr          string
	}{
		{
			desc: "basic 1",
			opts: &ServerOptions{
				MinTLSVersion: TLSVersion12,
				MaxTLSVersion: TLSVersion13,
				TLSCiphersuites: []Ciphersuite{
					CiphersuiteAES128GCMSHA256,
					CiphersuiteAES256GCMSHA384,
					CiphersuiteCHACHA20POLY1305SHA256},
				LocalIdentities: []Identity{
					&SpiffeID{"test spiffe id"},
					&Hostname{"test hostname"},
				},
				HSAddr: "test handshaker address",
			},
			outMinTLSVersion: TLSVersion12,
			outMaxTLSVersion: TLSVersion13,
			outTLSCiphersuites: []Ciphersuite{
				CiphersuiteAES128GCMSHA256,
				CiphersuiteAES256GCMSHA384,
				CiphersuiteCHACHA20POLY1305SHA256},
			outLocalIdentities: []Identity{
				&SpiffeID{"test spiffe id"},
				&Hostname{"test hostname"},
			},
			outHSAddr: "test handshaker address",
		},
		{
			desc: "basic 2",
			opts: &ServerOptions{
				MinTLSVersion: TLSVersion13,
				MaxTLSVersion: TLSVersion13,
				TLSCiphersuites: []Ciphersuite{
					CiphersuiteAES256GCMSHA384,
					CiphersuiteCHACHA20POLY1305SHA256},
				LocalIdentities: []Identity{
					&SpiffeID{"test spiffe id"},
				},
				HSAddr: "test handshaker address",
			},
			outMinTLSVersion: TLSVersion13,
			outMaxTLSVersion: TLSVersion13,
			outTLSCiphersuites: []Ciphersuite{
				CiphersuiteAES256GCMSHA384,
				CiphersuiteCHACHA20POLY1305SHA256},
			outLocalIdentities: []Identity{
				&SpiffeID{"test spiffe id"},
			},
			outHSAddr: "test handshaker address",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			c, err := NewServerCreds(tc.opts)
			if err != nil {
				t.Fatalf("NewServerCreds(&ServerOptions{}) failed: %v", err)
			}
			if got, want := c.Info().SecurityProtocol, s2aSecurityProtocol; got != want {
				t.Errorf("c.Info().SecurityProtocol = %v, want %v", got, want)
			}
			s2aCreds, ok := c.(*s2aTransportCreds)
			if !ok {
				t.Error("c.(*s2aTransportCreds) failed")
			}
			if got, want := s2aCreds.minTLSVersion, tc.outMinTLSVersion; got != want {
				t.Errorf("s2aCreds.minTLSVersion = %v, want %v", got, want)
			}
			if got, want := s2aCreds.maxTLSVersion, tc.outMaxTLSVersion; got != want {
				t.Errorf("s2aCreds.maxTLSVersion = %v, want %v", got, want)
			}
			if got, want := s2aCreds.tlsCiphersuites, tc.outTLSCiphersuites; !cmp.Equal(got, want) {
				t.Errorf("s2aCreds.tlsCiphersuites = %v, want %v", got, want)
			}
			if got, want := s2aCreds.localIdentities, tc.outLocalIdentities; !reflect.DeepEqual(got, want) {
				t.Errorf("s2aCreds.localIdentities = %v, want %v", got, want)
			}
			if got, want := s2aCreds.hsAddr, tc.outHSAddr; got != want {
				t.Errorf("s2aCreds.hsAddr = %v, want %v", got, want)
			}
		})
	}
}

func TestInfo(t *testing.T) {
	// This is not testing any handshaker functionality, so it's fine to only
	// use NewServerCreds and not NewClientCreds.
	c, err := NewServerCreds(&ServerOptions{})
	if err != nil {
		t.Fatalf("NewServerCreds(&ServerOptions{}) failed: %v", err)
	}
	info := c.Info()
	if got, want := info.ProtocolVersion, ""; got != want {
		t.Errorf("info.ProtocolVersion=%v, want %v", got, want)
	}
	if got, want := info.SecurityProtocol, "s2a"; got != want {
		t.Errorf("info.SecurityProtocol=%v, want %v", got, want)
	}
	if got, want := info.ServerName, ""; got != want {
		t.Errorf("info.ServerName=%v, want %v", got, want)
	}
}

func TestCloneClient(t *testing.T) {
	opt := &ClientOptions{
		MinTLSVersion: TLSVersion12,
		MaxTLSVersion: TLSVersion13,
		TLSCiphersuites: []Ciphersuite{
			CiphersuiteAES128GCMSHA256,
			CiphersuiteAES256GCMSHA384,
			CiphersuiteCHACHA20POLY1305SHA256},
		TargetIdentities: []Identity{
			&SpiffeID{"test spiffe id"},
			&Hostname{"test hostname"},
		},
		LocalIdentity: &Hostname{"test hostname"},
		HSAddr:        "test handshaker address",
	}
	c, err := NewClientCreds(opt)
	if err != nil {
		t.Fatalf("NewClientCreds(%v) failed: %v", opt, err)
	}
	cc := c.Clone()
	s2aCreds, ok := c.(*s2aTransportCreds)
	if !ok {
		t.Error("c.(*s2aTransportCreds) failed")
	}
	s2aCloneCreds, ok := cc.(*s2aTransportCreds)
	if !ok {
		t.Error("cc.(*s2aTransportCreds) failed")
	}
	if got, want := reflect.DeepEqual(s2aCreds, s2aCloneCreds), true; got != want {
		t.Errorf("reflect.DeepEqual(%v, %v) = %v, want %v", s2aCreds, s2aCloneCreds, got, want)
	}
	// Change the values and verify that the creds were deep copied.
	s2aCloneCreds.targetIdentities[0] = &SpiffeID{"new spiffe id"}
	if got, want := reflect.DeepEqual(s2aCreds, s2aCloneCreds), false; got != want {
		t.Errorf("reflect.DeepEqual(%v, %v) = %v, want %v", s2aCreds, s2aCloneCreds, got, want)
	}
}

func TestCloneServer(t *testing.T) {
	c, err := NewServerCreds(&ServerOptions{
		MinTLSVersion: TLSVersion12,
		MaxTLSVersion: TLSVersion13,
		TLSCiphersuites: []Ciphersuite{
			CiphersuiteAES128GCMSHA256,
			CiphersuiteAES256GCMSHA384,
			CiphersuiteCHACHA20POLY1305SHA256},
		LocalIdentities: []Identity{
			&SpiffeID{"test spiffe id"},
			&Hostname{"test hostname"},
		},
		HSAddr: "test handshaker address",
	})
	if err != nil {
		t.Fatalf("NewServerCreds(&ServerOptions{}) failed: %v", err)
	}
	cc := c.Clone()
	s2aCreds, ok := c.(*s2aTransportCreds)
	if !ok {
		t.Error("c.(*s2aTransportCreds) failed")
	}
	s2aCloneCreds, ok := cc.(*s2aTransportCreds)
	if !ok {
		t.Error("cc.(*s2aTransportCreds) failed")
	}
	if got, want := reflect.DeepEqual(s2aCreds, s2aCloneCreds), true; got != want {
		t.Errorf("reflect.DeepEqual(%v, %v) = %v, want %v", s2aCreds, s2aCloneCreds, got, want)
	}
	// Change the values and verify that the creds were deep copied.
	s2aCloneCreds.localIdentities[0] = &SpiffeID{"new spiffe id"}
	if got, want := reflect.DeepEqual(s2aCreds, s2aCloneCreds), false; got != want {
		t.Errorf("reflect.DeepEqual(%v, %v) = %v, want %v", s2aCreds, s2aCloneCreds, got, want)
	}
}

func TestOverrideServerName(t *testing.T) {
	wantServerName := "server.name"
	// This is not testing any handshaker functionality, so it's fine to only
	// use NewServerCreds and not NewClientCreds.
	c, err := NewServerCreds(&ServerOptions{})
	if err != nil {
		t.Fatalf("NewServerCreds(&ServerOptions{}) failed: %v", err)
	}
	if err := c.OverrideServerName(wantServerName); err != nil {
		t.Fatalf("c.OverrideServerName(%v) failed: %v", wantServerName, err)
	}
	if got, want := c.Info().ServerName, wantServerName; got != want {
		t.Fatalf("c.Info().ServerName = %v, want %v", got, want)
	}
}
