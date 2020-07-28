/*
 *
 * Copyright 2020 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Runs a Greeter service that uses S2A to establish secure connections with 
// greeter clients.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/security/s2a"
	pb "google.golang.org/grpc/security/s2a/examples/helloworld"
)

var (
	serverAddr    = flag.String("server_address", "localhost:50051", "The address of the gRPC server.")
	s2aServerAddr = flag.String("s2a_server_address", "localhost:61365", "S2A server address.")
)

// server is used to implement helloworld.GreeterServer.
type server struct {
	pb.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer
func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	log.Printf("Received: %v", in.GetName())
	return &pb.HelloReply{Message: "Hello, " + in.GetName() + "!"}, nil
}

func main() {
	flag.Parse()

	// Set up server-side S2A transport credentials.
	serverOpts := &s2a.ServerOptions{
		HandshakerServiceAddress: *s2aServerAddr,
	}
	creds, err := s2a.NewServerCreds(serverOpts)
	if err != nil {
		log.Fatalf("NewServerCreds(%v) failed: %v", serverOpts, err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf("%s", *serverAddr))
	if err != nil {
		log.Fatalf("failed to listen on address %s: %v", *serverAddr, err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
