package s2a

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	pb "google.golang.org/grpc/examples/helloworld/helloworld"
	"google.golang.org/grpc/security/s2a/internal/fakehandshaker/service"
	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

const (
	clientHandshakerPort = "50049"
	serverHandshakerPort = "50050"
	communicationPort    = "50051"
	serverAddress        = "localhost:" + communicationPort
	clientHostname       = "test_client_hostname"
	serverSpiffeId       = "test_server_spiffe_id"
)

// server is used to implement helloworld.GreeterServer.
type server struct {
	pb.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer
func (s *server) SayHello(_ context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	return &pb.HelloReply{Message: "Hello " + in.GetName()}, nil
}

func startClient(t *testing.T) {
	clientOpts := &ClientOptions{
		TargetIdentities:         []Identity{NewSpiffeID(serverSpiffeId)},
		LocalIdentity:            NewHostname(clientHostname),
		HandshakerServiceAddress: fmt.Sprintf("localhost:%v", clientHandshakerPort),
	}
	creds, err := NewClientCreds(clientOpts)
	if err != nil {
		t.Fatalf("NewClientCreds(%v) failed: %v", clientOpts, err)
	}
	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	}

	// Set up a connection to the server.
	conn, err := grpc.Dial(serverAddress, dialOptions...)
	if err != nil {
		t.Fatalf("grpc.Dial(%v, %v) failed: %v", serverAddress, dialOptions, err)
	}
	defer conn.Close()

	// Contact the server.
	c := pb.NewGreeterClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	req := &pb.HelloRequest{Name: clientHostname}
	r, err := c.SayHello(ctx, req)
	if err != nil {
		t.Fatalf("c.SayHello(%v, %v) failed: %v", ctx, req, err)
	}
	if got, want := r.GetMessage(), "Hello "+clientHostname; got != want {
		t.Errorf("r.GetMessage() = %v, want %v", got, want)
	}
}

func startServer(t *testing.T) {
	serverOpts := &ServerOptions{
		LocalIdentities:          []Identity{NewSpiffeID(serverSpiffeId)},
		HandshakerServiceAddress: fmt.Sprintf("localhost:%v", serverHandshakerPort),
	}
	creds, err := NewServerCreds(serverOpts)
	if err != nil {
		t.Fatalf("NewServerCreds(%v) failed: %v", serverOpts, err)
	}

	addr := fmt.Sprintf(":%s", communicationPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("net.Listen(tcp, %v) failed: %v", addr, err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		t.Fatalf("s.Serve(%v) failed: %v", lis, err)
	}
}

func startHandshaker(t *testing.T, port string) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		t.Fatalf("net.Listen(tcp, %v) failed: %v", port, err)
	}
	s := grpc.NewServer()
	s2apb.RegisterS2AServiceServer(s, &service.FakeHandshakerService{})
	if err := s.Serve(lis); err != nil {
		t.Fatalf("s.Serve(%v) failed: %v", lis, err)
	}
}

func TestE2EClientServerUsingFakeHS(t *testing.T) {
	go startHandshaker(t, clientHandshakerPort)
	go startHandshaker(t, serverHandshakerPort)
	go startServer(t)
	startClient(t)
}
