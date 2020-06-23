package main

import (
	"bytes"
	"flag"
	"fmt"
	"google.golang.org/grpc/codes"
	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
	"log"
	"net"

	"google.golang.org/grpc"
)

var (
	port = flag.String("port", "50051", "port number where the fake handshaker service will run")
)

type handshakeState int

const (
	// initial is the initial state of the handshaker before any handshake
	// message has been received.
	initial handshakeState = 0
	// started is the state of the handshaker when the handshake has been
	// initiated but no bytes have been sent or received.
	started handshakeState = 1
	// sent is the state of the handshaker when the handshake has been
	// initiated and bytes have been sent.
	sent handshakeState = 2
	// completed is the state of the handshaker when the handshake has been
	// completed.
	completed handshakeState = 3
)

const (
	grpcAppProtocol     = "grpc"
	clientHelloFrame    = "ClientHello"
	clientFinishedFrame = "ClientFinished"
	serverFrame         = "ServerHelloAndFinished"
)

// fakeHandshakerService implements the s2apb.S2AServiceServer. The fake
// handshaker service should not be used by more than 1 application at a time.
type fakeHandshakerService struct {
	assistingClient bool
	state           handshakeState
	peerIdentity    *s2apb.Identity
	localIdentity   *s2apb.Identity
}

// SetUpSession sets up the S2A session.
func (hs *fakeHandshakerService) SetUpSession(stream s2apb.S2AService_SetUpSessionServer) error {
	for {
		sessionReq, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("stream recv failed: %v", err)
		}
		if sessionReq == nil {
			return nil
		}

		var resp *s2apb.SessionResp
		switch req := sessionReq.ReqOneof.(type) {
		case *s2apb.SessionReq_ClientStart:
			resp = hs.processClientStart(req)
		case *s2apb.SessionReq_ServerStart:
			resp = hs.processServerStart(req)
		case *s2apb.SessionReq_Next:
			resp = hs.processNext(req)
		default:
			return fmt.Errorf("session request has unexpected type %T", req)
		}

		if err = stream.Send(resp); err != nil {
			return fmt.Errorf("stream send failed: %v", err)
		}
	}
}

// processClientStart processes a ClientSessionStartReq.
func (hs *fakeHandshakerService) processClientStart(req *s2apb.SessionReq_ClientStart) *s2apb.SessionResp {
	resp := s2apb.SessionResp{}
	if hs.state != initial {
		resp.Status = &s2apb.SessionStatus{Code: uint32(codes.FailedPrecondition), Details: "client start handshake not in initial state"}
		return &resp
	}
	if len(req.ClientStart.GetApplicationProtocols()) != 1 {
		resp.Status = &s2apb.SessionStatus{Code: uint32(codes.InvalidArgument), Details: "only one application protocol must be passed"}
		return &resp
	}
	if req.ClientStart.GetApplicationProtocols()[0] != grpcAppProtocol {
		resp.Status = &s2apb.SessionStatus{Code: uint32(codes.InvalidArgument), Details: "application protocol was not grpc"}
		return &resp
	}
	if req.ClientStart.GetMaxTlsVersion() != s2apb.TLSVersion_TLS1_3 {
		resp.Status = &s2apb.SessionStatus{Code: uint32(codes.InvalidArgument), Details: "max TLS version must be 1.3"}
		return &resp
	}
	resp.OutFrames = []byte(clientHelloFrame)
	resp.BytesConsumed = 0
	resp.Status = &s2apb.SessionStatus{Code: uint32(codes.OK)}
	hs.localIdentity = req.ClientStart.LocalIdentity
	if len(req.ClientStart.TargetIdentities) > 0 {
		hs.peerIdentity = req.ClientStart.TargetIdentities[0]
	}
	hs.assistingClient = true
	hs.state = sent
	return &resp
}

// processServerStart processes a ServerSessionStartReq.
func (hs *fakeHandshakerService) processServerStart(req *s2apb.SessionReq_ServerStart) *s2apb.SessionResp {
	resp := s2apb.SessionResp{}
	if hs.state != initial {
		resp.Status = &s2apb.SessionStatus{Code: uint32(codes.FailedPrecondition), Details: "server start handshake not in initial state"}
		return &resp
	}
	if len(req.ServerStart.GetApplicationProtocols()) != 1 {
		resp.Status = &s2apb.SessionStatus{Code: uint32(codes.InvalidArgument), Details: "only one application protocol must be passed"}
		return &resp
	}
	if req.ServerStart.GetApplicationProtocols()[0] != grpcAppProtocol {
		resp.Status = &s2apb.SessionStatus{Code: uint32(codes.InvalidArgument), Details: "application protocol was not grpc"}
		return &resp
	}
	if req.ServerStart.GetMaxTlsVersion() != s2apb.TLSVersion_TLS1_3 {
		resp.Status = &s2apb.SessionStatus{Code: uint32(codes.InvalidArgument), Details: "max TLS version must be 1.3"}
		return &resp
	}

	if len(req.ServerStart.InBytes) == 0 {
		resp.BytesConsumed = 0
		hs.state = started
	} else if bytes.Equal(req.ServerStart.InBytes, []byte(clientHelloFrame)) {
		resp.OutFrames = []byte(serverFrame)
		resp.BytesConsumed = uint32(len(clientHelloFrame))
		hs.state = sent
	} else {
		resp.Status = &s2apb.SessionStatus{Code: uint32(codes.Unknown)}
		return &resp
	}

	resp.Status = &s2apb.SessionStatus{Code: uint32(codes.OK)}
	if len(req.ServerStart.LocalIdentities) > 0 {
		hs.localIdentity = req.ServerStart.LocalIdentities[0]
	}
	hs.assistingClient = false
	return &resp
}

// processNext processes a SessionNext request.
func (hs *fakeHandshakerService) processNext(req *s2apb.SessionReq_Next) *s2apb.SessionResp {
	resp := s2apb.SessionResp{}
	if hs.assistingClient {
		if hs.state != sent {
			resp.Status = &s2apb.SessionStatus{Code: uint32(codes.FailedPrecondition), Details: "client handshake was not in sent state"}
			return &resp
		}
		if !bytes.Equal(req.Next.InBytes, []byte(serverFrame)) {
			resp.Status = &s2apb.SessionStatus{Code: uint32(codes.Unknown), Details: "client request did not match server frame"}
			return &resp
		}
		resp.OutFrames = []byte(clientFinishedFrame)
		resp.BytesConsumed = uint32(len(serverFrame))
		hs.state = completed
	} else {
		if hs.state == started {
			if !bytes.Equal(req.Next.InBytes, []byte(clientHelloFrame)) {
				resp.Status = &s2apb.SessionStatus{Code: uint32(codes.Unknown), Details: "server request did not match client hello frame"}
				return &resp
			}
			resp.OutFrames = []byte(serverFrame)
			resp.BytesConsumed = uint32(len(clientHelloFrame))
			hs.state = sent
		} else if hs.state == sent {
			if !bytes.Equal(req.Next.InBytes[:len(clientFinishedFrame)], []byte(clientFinishedFrame)) {
				resp.Status = &s2apb.SessionStatus{Code: uint32(codes.Unknown), Details: "server request did not match client finished frame"}
				return &resp
			}
			resp.BytesConsumed = uint32(len(clientFinishedFrame))
			hs.state = completed
		} else {
			resp.Status = &s2apb.SessionStatus{Code: uint32(codes.FailedPrecondition), Details: "server request was not in expected state"}
			return &resp
		}
	}
	resp.Status = &s2apb.SessionStatus{Code: uint32(codes.OK)}
	if hs.state == completed {
		resp.Result = hs.getSessionResult()
	}
	return &resp
}

// getSessionResult returns a dummy SessionResult.
func (hs *fakeHandshakerService) getSessionResult() *s2apb.SessionResult {
	res := s2apb.SessionResult{}
	res.ApplicationProtocol = grpcAppProtocol
	res.State = &s2apb.SessionState{
		TlsVersion:     s2apb.TLSVersion_TLS1_3,
		TlsCiphersuite: s2apb.Ciphersuite_AES_128_GCM_SHA256,
		InKey:          []byte("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"),
		OutKey:         []byte("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"),
	}
	res.PeerIdentity = hs.peerIdentity
	res.LocalIdentity = hs.localIdentity
	return &res
}

func main() {
	flag.Parse()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %s: %v", *port, err)
	}
	s := grpc.NewServer()
	s2apb.RegisterS2AServiceServer(s, &fakeHandshakerService{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
