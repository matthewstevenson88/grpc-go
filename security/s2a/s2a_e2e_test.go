package s2a

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	pb "google.golang.org/grpc/examples/helloworld/helloworld"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/security/s2a/internal/fakehandshaker/service"
	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

var (
	clientHandshakerAddr string
	serverHandshakerAddr string
	serverAddr           string
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

func startClient(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	req := &pb.HelloRequest{Name: clientMessage}
	grpclog.Infof("client calling SayHello with request: %v", req)
	resp, err := c.SayHello(ctx, req)
	if err != nil {
		t.Fatalf("c.SayHello(%v, %v) failed: %v", ctx, req, err)
	}
	if got, want := resp.GetMessage(), "Hello "+clientMessage; got != want {
		t.Errorf("r.GetMessage() = %v, want %v", got, want)
	}
}

func startServer(t *testing.T, wg *sync.WaitGroup) {
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
	serverAddr = lis.Addr().String()
	grpclog.Infof("server running at address: %v", serverAddr)
	wg.Done()
	s := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		t.Fatalf("s.Serve(%v) failed: %v", lis, err)
	}
}

func startFakeHandshakerServer(t *testing.T, wg *sync.WaitGroup, forClient bool) {
	lis, err := net.Listen("tcp", ":")
	if err != nil {
		t.Fatalf("net.Listen(tcp, :0) failed: %v", err)
	}
	if forClient {
		clientHandshakerAddr = lis.Addr().String()
		grpclog.Infof("fake handshaker for client running at address: %v", clientHandshakerAddr)
	} else {
		serverHandshakerAddr = lis.Addr().String()
		grpclog.Infof("fake handshaker for server running at address: %v", serverHandshakerAddr)
	}
	wg.Done()
	s := grpc.NewServer()
	s2apb.RegisterS2AServiceServer(s, &service.FakeHandshakerService{})
	if err := s.Serve(lis); err != nil {
		t.Fatalf("s.Serve(%v) failed: %v", lis, err)
	}
}

func TestE2EClientServerUsingFakeHS(t *testing.T) {
	var wg sync.WaitGroup

	// Start up the handshakers and wait for them to set clientHandshakerAddr
	// and serverHandshakerAddr based on the addresses that are automatically
	// selected by net.Listen. We use 2 handshaker services because the fake
	// handshaker is set up to only handle 1 connection.
	wg.Add(2)
	go startFakeHandshakerServer(t, &wg, true /* forClient */)
	go startFakeHandshakerServer(t, &wg, false /* forClient */)
	wg.Wait()

	// Start up the server and wait for it to set serverAddr based on the
	// address that is automatically selected by net.Listen.
	wg.Add(1)
	go startServer(t, &wg)
	wg.Wait()

	// Finally, start up the client.
	startClient(t)
}
