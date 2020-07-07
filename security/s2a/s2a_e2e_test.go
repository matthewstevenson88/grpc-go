package s2a

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	pb "google.golang.org/grpc/examples/helloworld/helloworld"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/security/s2a/internal/fakehandshaker/service"
	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

const (
	clientHostname = "test_client_hostname"
	serverSpiffeId = "test_server_spiffe_id"
	clientMessage  = "echo"
)

// server is used to implement helloworld.GreeterServer.
type server struct {
	pb.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer.
func (s *server) SayHello(_ context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	return &pb.HelloReply{Message: "Hello " + in.GetName()}, nil
}

// startFakeHandshakerServer starts up a fake handshaker server and returns the
// address that it is listening on.
func startFakeHandshakerServer(t *testing.T) string {
	lis, err := net.Listen("tcp", ":")
	if err != nil {
		t.Fatalf("net.Listen(tcp, :0) failed: %v", err)
	}
	s := grpc.NewServer()
	s2apb.RegisterS2AServiceServer(s, &service.FakeHandshakerService{})
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Fatalf("s.Serve(%v) failed: %v", lis, err)
		}
	}()
	return lis.Addr().String()
}

// startServer starts up a server and returns the address that it is listening
// on.
func startServer(t *testing.T, serverHandshakerAddr string) string {
	serverOpts := &ServerOptions{
		LocalIdentities:          []Identity{NewSpiffeID(serverSpiffeId)},
		HandshakerServiceAddress: serverHandshakerAddr,
	}
	creds, err := NewServerCreds(serverOpts)
	if err != nil {
		t.Fatalf("NewServerCreds(%v) failed: %v", serverOpts, err)
	}

	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("net.Listen(tcp, :0) failed: %v", err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterGreeterServer(s, &server{})
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Fatalf("s.Serve(%v) failed: %v", lis, err)
		}
	}()
	return lis.Addr().String()
}

// runClient starts up a client and calls the server.
func runClient(t *testing.T, ctx context.Context, serverAddr, clientHandshakerAddr string) {
	clientOpts := &ClientOptions{
		TargetIdentities:         []Identity{NewSpiffeID(serverSpiffeId)},
		LocalIdentity:            NewHostname(clientHostname),
		HandshakerServiceAddress: clientHandshakerAddr,
	}
	creds, err := NewClientCreds(clientOpts)
	if err != nil {
		t.Fatalf("NewClientCreds(%v) failed: %v", clientOpts, err)
	}
	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	}

	grpclog.Info("client dialing server at address: %v", serverAddr)
	// Establish a connection to the server.
	conn, err := grpc.Dial(serverAddr, dialOptions...)
	if err != nil {
		t.Fatalf("grpc.Dial(%v, %v) failed: %v", serverAddr, dialOptions, err)
	}
	defer conn.Close()

	// Contact the server.
	c := pb.NewGreeterClient(conn)
	req := &pb.HelloRequest{Name: clientMessage}
	grpclog.Infof("client calling SayHello with request: %v", req)
	resp, err := c.SayHello(ctx, req, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("c.SayHello(%v, %v) failed: %v", ctx, req, err)
	}
	if got, want := resp.GetMessage(), "Hello "+clientMessage; got != want {
		t.Errorf("r.GetMessage() = %v, want %v", got, want)
	}
}

func TestE2EClientServerUsingFakeHS(t *testing.T) {
	// Start the handshaker servers for the client and server.
	serverHandshakerAddr := startFakeHandshakerServer(t)
	grpclog.Infof("fake handshaker for server running at address: %v", serverHandshakerAddr)
	clientHandshakerAddr := startFakeHandshakerServer(t)
	grpclog.Infof("fake handshaker for client running at address: %v", clientHandshakerAddr)

	// Start the server.
	serverAddr := startServer(t, serverHandshakerAddr)
	grpclog.Infof("server running at address: %v", serverAddr)

	// Finally, start up the client.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	runClient(t, ctx, serverAddr, clientHandshakerAddr)
}
