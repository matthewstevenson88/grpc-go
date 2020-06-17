package main

import (
	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	s2a_proto "google.golang.org/grpc/security/s2a/internal/proto"
	"testing"
)

type fakeS2ASetupSessionServer struct {
	grpc.ServerStream
	recvCount int
	reqs      []*s2a_proto.SessionReq
	resps     []*s2a_proto.SessionResp
}

func (f *fakeS2ASetupSessionServer) Send(resp *s2a_proto.SessionResp) error {
	f.resps = append(f.resps, resp)
	return nil
}

func (f *fakeS2ASetupSessionServer) Recv() (*s2a_proto.SessionReq, error) {
	if f.recvCount == len(f.reqs) {
		return nil, nil
	}
	req := f.reqs[f.recvCount]
	f.recvCount++
	return req, nil
}

func TestSetupSession(t *testing.T) {
	for _, tc := range []struct {
		desc string
		// Note that outResps[i] is the output for reqs[i].
		reqs           []*s2a_proto.SessionReq
		outResps       []*s2a_proto.SessionResp
		hasNonOKStatus bool
	}{
		{
			desc: "client failure no app protocols",
			reqs: []*s2a_proto.SessionReq{
				{
					ReqOneof: &s2a_proto.SessionReq_ClientStart{
						ClientStart: &s2a_proto.ClientSessionStartReq{},
					},
				},
			},
			hasNonOKStatus: true,
		},
		{
			desc: "client failure non initial state",
			reqs: []*s2a_proto.SessionReq{
				{
					ReqOneof: &s2a_proto.SessionReq_ClientStart{
						ClientStart: &s2a_proto.ClientSessionStartReq{
							ApplicationProtocols: []string{"app protocol"},
							MinTlsVersion:        s2a_proto.TLSVersion_TLS1_3,
							MaxTlsVersion:        s2a_proto.TLSVersion_TLS1_3,
							TlsCiphersuites: []s2a_proto.Ciphersuite{
								s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
								s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
								s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
						},
					},
				},
				{
					ReqOneof: &s2a_proto.SessionReq_ClientStart{
						ClientStart: &s2a_proto.ClientSessionStartReq{
							ApplicationProtocols: []string{"app protocol"},
							MinTlsVersion:        s2a_proto.TLSVersion_TLS1_3,
							MaxTlsVersion:        s2a_proto.TLSVersion_TLS1_3,
							TlsCiphersuites: []s2a_proto.Ciphersuite{
								s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
								s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
								s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
						},
					},
				},
			},
			outResps: []*s2a_proto.SessionResp{
				{
					OutFrames: []byte(ClientInitFrame),
					Status: &s2a_proto.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
			},
			hasNonOKStatus: true,
		},
		{
			desc: "client test",
			reqs: []*s2a_proto.SessionReq{
				{
					ReqOneof: &s2a_proto.SessionReq_ClientStart{
						ClientStart: &s2a_proto.ClientSessionStartReq{
							ApplicationProtocols: []string{"app protocol"},
							MinTlsVersion:        s2a_proto.TLSVersion_TLS1_3,
							MaxTlsVersion:        s2a_proto.TLSVersion_TLS1_3,
							TlsCiphersuites: []s2a_proto.Ciphersuite{
								s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
								s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
								s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
						},
					},
				},
				{
					ReqOneof: &s2a_proto.SessionReq_Next{
						Next: &s2a_proto.SessionNextReq{
							InBytes: []byte(ServerFrame),
						},
					},
				},
			},
			outResps: []*s2a_proto.SessionResp{
				{
					OutFrames: []byte(ClientInitFrame),
					Status: &s2a_proto.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
				{
					OutFrames:     []byte(ClientFinishFrame),
					BytesConsumed: uint32(len(ServerFrame)),
					Result:        getSessionResult(),
					Status: &s2a_proto.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
			},
		},
		{
			desc: "server failure no app protocols",
			reqs: []*s2a_proto.SessionReq{
				{
					ReqOneof: &s2a_proto.SessionReq_ServerStart{
						ServerStart: &s2a_proto.ServerSessionStartReq{},
					},
				},
			},
			hasNonOKStatus: true,
		},
		{
			desc: "server failure non initial state",
			reqs: []*s2a_proto.SessionReq{
				{
					ReqOneof: &s2a_proto.SessionReq_ServerStart{
						ServerStart: &s2a_proto.ServerSessionStartReq{
							ApplicationProtocols: []string{"app protocol"},
							MinTlsVersion:        s2a_proto.TLSVersion_TLS1_3,
							MaxTlsVersion:        s2a_proto.TLSVersion_TLS1_3,
							TlsCiphersuites: []s2a_proto.Ciphersuite{
								s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
								s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
								s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
						},
					},
				},
				{
					ReqOneof: &s2a_proto.SessionReq_ServerStart{
						ServerStart: &s2a_proto.ServerSessionStartReq{
							ApplicationProtocols: []string{"app protocol"},
							MinTlsVersion:        s2a_proto.TLSVersion_TLS1_3,
							MaxTlsVersion:        s2a_proto.TLSVersion_TLS1_3,
							TlsCiphersuites: []s2a_proto.Ciphersuite{
								s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
								s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
								s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
						},
					},
				},
			},
			outResps: []*s2a_proto.SessionResp{
				{
					Status: &s2a_proto.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
			},
			hasNonOKStatus: true,
		},
		{
			desc: "server test",
			reqs: []*s2a_proto.SessionReq{
				{
					ReqOneof: &s2a_proto.SessionReq_ServerStart{
						ServerStart: &s2a_proto.ServerSessionStartReq{
							ApplicationProtocols: []string{"app protocol"},
							MinTlsVersion:        s2a_proto.TLSVersion_TLS1_3,
							MaxTlsVersion:        s2a_proto.TLSVersion_TLS1_3,
							TlsCiphersuites: []s2a_proto.Ciphersuite{
								s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
								s2a_proto.Ciphersuite_AES_256_GCM_SHA384,
								s2a_proto.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
							InBytes: []byte(ClientInitFrame),
						},
					},
				},
				{
					ReqOneof: &s2a_proto.SessionReq_Next{
						Next: &s2a_proto.SessionNextReq{
							InBytes: []byte(ClientFinishFrame),
						},
					},
				},
			},
			outResps: []*s2a_proto.SessionResp{
				{
					OutFrames:     []byte(ServerFrame),
					BytesConsumed: uint32(len(ClientInitFrame)),
					Status: &s2a_proto.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
				{
					BytesConsumed: uint32(len(ClientFinishFrame)),
					Result:        getSessionResult(),
					Status: &s2a_proto.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			hs := fakeHandshakerService{}
			stream := &fakeS2ASetupSessionServer{reqs: tc.reqs}
			if err := hs.SetUpSession(stream); err != nil {
				t.Errorf("hs.SetUpSession failed: %v", err)
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
