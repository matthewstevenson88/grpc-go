package main

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

type fakeS2ASetupSessionServer struct {
	grpc.ServerStream
	recvCount int
	reqs      []*s2apb.SessionReq
	resps     []*s2apb.SessionResp
}

func (f *fakeS2ASetupSessionServer) Send(resp *s2apb.SessionResp) error {
	f.resps = append(f.resps, resp)
	return nil
}

func (f *fakeS2ASetupSessionServer) Recv() (*s2apb.SessionReq, error) {
	if f.recvCount == len(f.reqs) {
		return nil, errors.New("request buffer was fully exhausted")
	}
	req := f.reqs[f.recvCount]
	f.recvCount++
	return req, nil
}

func TestSetupSession(t *testing.T) {
	for _, tc := range []struct {
		desc string
		// Note that outResps[i] is the output for reqs[i].
		reqs           []*s2apb.SessionReq
		outResps       []*s2apb.SessionResp
		hasNonOKStatus bool
	}{
		{
			desc: "client failure no app protocols",
			reqs: []*s2apb.SessionReq{
				{
					ReqOneof: &s2apb.SessionReq_ClientStart{
						ClientStart: &s2apb.ClientSessionStartReq{},
					},
				},
			},
			hasNonOKStatus: true,
		},
		{
			desc: "client failure non initial state",
			reqs: []*s2apb.SessionReq{
				{
					ReqOneof: &s2apb.SessionReq_ClientStart{
						ClientStart: &s2apb.ClientSessionStartReq{
							ApplicationProtocols: []string{grpcAppProtocol},
							MinTlsVersion:        s2apb.TLSVersion_TLS1_3,
							MaxTlsVersion:        s2apb.TLSVersion_TLS1_3,
							TlsCiphersuites: []s2apb.Ciphersuite{
								s2apb.Ciphersuite_AES_128_GCM_SHA256,
								s2apb.Ciphersuite_AES_256_GCM_SHA384,
								s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
						},
					},
				},
				{
					ReqOneof: &s2apb.SessionReq_ClientStart{
						ClientStart: &s2apb.ClientSessionStartReq{
							ApplicationProtocols: []string{grpcAppProtocol},
							MinTlsVersion:        s2apb.TLSVersion_TLS1_3,
							MaxTlsVersion:        s2apb.TLSVersion_TLS1_3,
							TlsCiphersuites: []s2apb.Ciphersuite{
								s2apb.Ciphersuite_AES_128_GCM_SHA256,
								s2apb.Ciphersuite_AES_256_GCM_SHA384,
								s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
						},
					},
				},
			},
			outResps: []*s2apb.SessionResp{
				{
					OutFrames: []byte(clientHelloFrame),
					Status: &s2apb.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
			},
			hasNonOKStatus: true,
		},
		{
			desc: "client test",
			reqs: []*s2apb.SessionReq{
				{
					ReqOneof: &s2apb.SessionReq_ClientStart{
						ClientStart: &s2apb.ClientSessionStartReq{
							ApplicationProtocols: []string{grpcAppProtocol},
							MinTlsVersion:        s2apb.TLSVersion_TLS1_3,
							MaxTlsVersion:        s2apb.TLSVersion_TLS1_3,
							TlsCiphersuites: []s2apb.Ciphersuite{
								s2apb.Ciphersuite_AES_128_GCM_SHA256,
								s2apb.Ciphersuite_AES_256_GCM_SHA384,
								s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
							LocalIdentity: &s2apb.Identity{
								IdentityOneof: &s2apb.Identity_Hostname{Hostname: "local hostname"},
							},
							TargetIdentities: []*s2apb.Identity{
								{
									IdentityOneof: &s2apb.Identity_SpiffeId{SpiffeId: "peer spiffe identity"},
								},
							},
						},
					},
				},
				{
					ReqOneof: &s2apb.SessionReq_Next{
						Next: &s2apb.SessionNextReq{
							InBytes: []byte(serverFrame),
						},
					},
				},
			},
			outResps: []*s2apb.SessionResp{
				{
					OutFrames: []byte(clientHelloFrame),
					Status: &s2apb.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
				{
					OutFrames:     []byte(clientFinishedFrame),
					BytesConsumed: uint32(len(serverFrame)),
					Result: &s2apb.SessionResult{
						ApplicationProtocol: grpcAppProtocol,
						State: &s2apb.SessionState{
							TlsVersion:     s2apb.TLSVersion_TLS1_3,
							TlsCiphersuite: s2apb.Ciphersuite_AES_128_GCM_SHA256,
							InKey:          []byte(inKey),
							OutKey:         []byte(outKey),
						},
						PeerIdentity: &s2apb.Identity{
							IdentityOneof: &s2apb.Identity_SpiffeId{SpiffeId: "peer spiffe identity"},
						},
						LocalIdentity: &s2apb.Identity{
							IdentityOneof: &s2apb.Identity_Hostname{Hostname: "local hostname"},
						},
					},
					Status: &s2apb.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
			},
		},
		{
			desc: "server failure no app protocols",
			reqs: []*s2apb.SessionReq{
				{
					ReqOneof: &s2apb.SessionReq_ServerStart{
						ServerStart: &s2apb.ServerSessionStartReq{},
					},
				},
			},
			hasNonOKStatus: true,
		},
		{
			desc: "server failure non initial state",
			reqs: []*s2apb.SessionReq{
				{
					ReqOneof: &s2apb.SessionReq_ServerStart{
						ServerStart: &s2apb.ServerSessionStartReq{
							ApplicationProtocols: []string{grpcAppProtocol},
							MinTlsVersion:        s2apb.TLSVersion_TLS1_3,
							MaxTlsVersion:        s2apb.TLSVersion_TLS1_3,
							TlsCiphersuites: []s2apb.Ciphersuite{
								s2apb.Ciphersuite_AES_128_GCM_SHA256,
								s2apb.Ciphersuite_AES_256_GCM_SHA384,
								s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
						},
					},
				},
				{
					ReqOneof: &s2apb.SessionReq_ServerStart{
						ServerStart: &s2apb.ServerSessionStartReq{
							ApplicationProtocols: []string{grpcAppProtocol},
							MinTlsVersion:        s2apb.TLSVersion_TLS1_3,
							MaxTlsVersion:        s2apb.TLSVersion_TLS1_3,
							TlsCiphersuites: []s2apb.Ciphersuite{
								s2apb.Ciphersuite_AES_128_GCM_SHA256,
								s2apb.Ciphersuite_AES_256_GCM_SHA384,
								s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
						},
					},
				},
			},
			outResps: []*s2apb.SessionResp{
				{
					Status: &s2apb.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
			},
			hasNonOKStatus: true,
		},
		{
			desc: "server test",
			reqs: []*s2apb.SessionReq{
				{
					ReqOneof: &s2apb.SessionReq_ServerStart{
						ServerStart: &s2apb.ServerSessionStartReq{
							ApplicationProtocols: []string{grpcAppProtocol},
							MinTlsVersion:        s2apb.TLSVersion_TLS1_3,
							MaxTlsVersion:        s2apb.TLSVersion_TLS1_3,
							TlsCiphersuites: []s2apb.Ciphersuite{
								s2apb.Ciphersuite_AES_128_GCM_SHA256,
								s2apb.Ciphersuite_AES_256_GCM_SHA384,
								s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
							InBytes: []byte(clientHelloFrame),
							LocalIdentities: []*s2apb.Identity{
								{
									IdentityOneof: &s2apb.Identity_Hostname{Hostname: "local hostname"},
								},
							},
						},
					},
				},
				{
					ReqOneof: &s2apb.SessionReq_Next{
						Next: &s2apb.SessionNextReq{
							InBytes: []byte(clientFinishedFrame),
						},
					},
				},
			},
			outResps: []*s2apb.SessionResp{
				{
					OutFrames:     []byte(serverFrame),
					BytesConsumed: uint32(len(clientHelloFrame)),
					Status: &s2apb.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
				{
					BytesConsumed: uint32(len(clientFinishedFrame)),
					Result: &s2apb.SessionResult{
						ApplicationProtocol: grpcAppProtocol,
						State: &s2apb.SessionState{
							TlsVersion:     s2apb.TLSVersion_TLS1_3,
							TlsCiphersuite: s2apb.Ciphersuite_AES_128_GCM_SHA256,
							InKey:          []byte(inKey),
							OutKey:         []byte(outKey),
						},
						LocalIdentity: &s2apb.Identity{
							IdentityOneof: &s2apb.Identity_Hostname{Hostname: "local hostname"},
						},
					},
					Status: &s2apb.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			hs := fakeHandshakerService{}
			stream := &fakeS2ASetupSessionServer{reqs: tc.reqs}
			if got, want := hs.SetUpSession(stream) == nil, !tc.hasNonOKStatus; got != want {
				t.Errorf("hs.SetUpSession(%v) = (err=nil) = %v, want %v", stream, got, want)
			}
			hasNonOKStatus := false
			for i := range tc.reqs {
				if stream.resps[i].Status.Code != uint32(codes.OK) {
					hasNonOKStatus = true
					break
				}
				if got, want := stream.resps[i], tc.outResps[i]; !cmp.Equal(got, want) {
					t.Fatalf("stream.resps[%d] = %v, want %v", i, got, want)
				}
			}
			if got, want := hasNonOKStatus, tc.hasNonOKStatus; got != want {
				t.Errorf("hasNonOKStatus = %v, want %v", got, want)
			}
		})
	}
}
