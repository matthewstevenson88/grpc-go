package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

var (
	port = flag.String("port", "50051", "port number where the fake handshaker service will run")
)

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
