package main

import (
	"bytes"
	"flag"
	"fmt"
	"google.golang.org/grpc/codes"
	s2a_proto "google.golang.org/grpc/security/s2a/internal/proto"
	"log"
	"net"

	"google.golang.org/grpc"
)

var (
	port = flag.String("port", "50051", "port number to use for connection")
)

type HandshakeState int

const (
	Initial   HandshakeState = 0
	Started   HandshakeState = 1
	Sent      HandshakeState = 2
	Completed HandshakeState = 3
)

const (
	ClientInitFrame   = "ClientInit"
	ClientFinishFrame = "ClientFinished"
	ServerFrame       = "ServerInitAndFinished"
)

// fakeHandshakerService is used to implement s2a_proto.S2AServiceServer.
type fakeHandshakerService struct {
	isClient       bool
	handshakeState HandshakeState
}

func (hs *fakeHandshakerService) SetUpSession(stream s2a_proto.S2AService_SetUpSessionServer) error {
	for {
		sessionReq, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("stream recv failed: %v", err)
		}
		if sessionReq == nil {
			return nil
		}

		var resp *s2a_proto.SessionResp
		switch req := sessionReq.ReqOneof.(type) {
		case *s2a_proto.SessionReq_ClientStart:
			resp = hs.processClientStart(req)
		case *s2a_proto.SessionReq_ServerStart:
			resp = hs.processServerStart(req)
		case *s2a_proto.SessionReq_Next:
			resp = hs.processNext(req)
		default:
			return fmt.Errorf("session request has unexpected type %T", req)
		}

		if err = stream.Send(resp); err != nil {
			return fmt.Errorf("stream send failed: %v", err)
		}
	}
}

func (hs *fakeHandshakerService) processClientStart(req *s2a_proto.SessionReq_ClientStart) *s2a_proto.SessionResp {
	resp := s2a_proto.SessionResp{}
	if hs.handshakeState != Initial {
		resp.Status = &s2a_proto.SessionStatus{Code: uint32(codes.FailedPrecondition)}
		return &resp
	}
	if len(req.ClientStart.GetApplicationProtocols()) == 0 {
		resp.Status = &s2a_proto.SessionStatus{Code: uint32(codes.InvalidArgument)}
		return &resp
	}

	resp.OutFrames = []byte(ClientInitFrame)
	resp.BytesConsumed = 0
	resp.Status = &s2a_proto.SessionStatus{Code: uint32(codes.OK)}
	hs.isClient = true
	hs.handshakeState = Sent
	return &resp
}

func (hs *fakeHandshakerService) processServerStart(req *s2a_proto.SessionReq_ServerStart) *s2a_proto.SessionResp {
	resp := s2a_proto.SessionResp{}
	if hs.handshakeState != Initial {
		resp.Status = &s2a_proto.SessionStatus{Code: uint32(codes.FailedPrecondition)}
		return &resp
	}
	if len(req.ServerStart.GetApplicationProtocols()) == 0 {
		resp.Status = &s2a_proto.SessionStatus{Code: uint32(codes.InvalidArgument)}
		return &resp
	}

	if len(req.ServerStart.InBytes) == 0 {
		resp.BytesConsumed = 0
		hs.handshakeState = Started
	} else if bytes.Equal(req.ServerStart.InBytes, []byte(ClientInitFrame)) {
		resp.OutFrames = []byte(ServerFrame)
		resp.BytesConsumed = uint32(len(ClientInitFrame))
		hs.handshakeState = Sent
	} else {
		resp.Status = &s2a_proto.SessionStatus{Code: uint32(codes.Unknown)}
		return &resp
	}

	resp.Status = &s2a_proto.SessionStatus{Code: uint32(codes.OK)}
	hs.isClient = false
	return &resp
}

func (hs *fakeHandshakerService) processNext(req *s2a_proto.SessionReq_Next) *s2a_proto.SessionResp {
	resp := s2a_proto.SessionResp{}
	if hs.isClient {
		if hs.handshakeState != Sent {
			resp.Status = &s2a_proto.SessionStatus{Code: uint32(codes.FailedPrecondition)}
			return &resp
		}
		if !bytes.Equal(req.Next.InBytes, []byte(ServerFrame)) {
			resp.Status = &s2a_proto.SessionStatus{Code: uint32(codes.Unknown)}
			return &resp
		}
		resp.OutFrames = []byte(ClientFinishFrame)
		resp.BytesConsumed = uint32(len(ServerFrame))
		hs.handshakeState = Completed
	} else {
		if hs.handshakeState == Started {
			if !bytes.Equal(req.Next.InBytes, []byte(ClientInitFrame)) {
				resp.Status = &s2a_proto.SessionStatus{Code: uint32(codes.Unknown)}
				return &resp
			}
			resp.OutFrames = []byte(ServerFrame)
			resp.BytesConsumed = uint32(len(ClientInitFrame))
			hs.handshakeState = Sent
		} else if hs.handshakeState == Sent {
			if !bytes.Equal(req.Next.InBytes[:len(ClientFinishFrame)], []byte(ClientFinishFrame)) {
				resp.Status = &s2a_proto.SessionStatus{Code: uint32(codes.Unknown)}
				return &resp
			}
			resp.BytesConsumed = uint32(len(ClientFinishFrame))
			hs.handshakeState = Completed
		} else {
			resp.Status = &s2a_proto.SessionStatus{Code: uint32(codes.FailedPrecondition)}
			return &resp
		}
	}
	resp.Status = &s2a_proto.SessionStatus{Code: uint32(codes.OK)}
	if hs.handshakeState == Completed {
		resp.Result = getSessionResult()
	}
	return &resp
}

func getSessionResult() *s2a_proto.SessionResult {
	res := s2a_proto.SessionResult{}
	res.ApplicationProtocol = "app protocol"
	res.State = &s2a_proto.SessionState{
		TlsVersion:     s2a_proto.TLSVersion_TLS1_3,
		TlsCiphersuite: s2a_proto.Ciphersuite_AES_128_GCM_SHA256,
	}
	res.PeerIdentity = &s2a_proto.Identity{
		IdentityOneof: &s2a_proto.Identity_SpiffeId{SpiffeId: "peer spiffe identity"},
	}
	res.LocalIdentity = &s2a_proto.Identity{
		IdentityOneof: &s2a_proto.Identity_Hostname{Hostname: "local hostname"},
	}
	return &res
}

func main() {
	flag.Parse()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %s: %v", *port, err)
	}
	s := grpc.NewServer()
	s2a_proto.RegisterS2AServiceServer(s, &fakeHandshakerService{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
