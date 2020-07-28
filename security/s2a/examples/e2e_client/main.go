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

// Package main implements a client for Greeter service that uses S2A.
package main

import (
	"context"
	"flag"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/security/s2a"
	pb "google.golang.org/grpc/security/s2a/examples/helloworld"
)

var (
	serverAddr = flag.String("server_address", "localhost:50050", "address of the server")
	s2aPort    = flag.String("s2a_port", "50052", "port number to use for the s2a connection")
)

func main() {
	flag.Parse()

	// Set up the client credentials.
	clientOpts := &s2a.ClientOptions{
		TargetIdentities:         []s2a.Identity{s2a.NewSpiffeID(*serverAddr)},
		LocalIdentity:            s2a.NewHostname("localhost"),
		HandshakerServiceAddress: "localhost:" + *s2aPort,
	}
	creds, err := s2a.NewClientCreds(clientOpts)
	if err != nil {
		log.Fatalf("could not create s2a client credentials: %v", err)
	}

	// Set up a connection to the server.
	conn, err := grpc.Dial(*serverAddr, grpc.WithTransportCredentials(creds), grpc.WithBlock())
	if err != nil {
		log.Fatalf("could not connect to server at %s: %v", *serverAddr, err)
	}
	defer conn.Close()
	c := pb.NewGreeterClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.SayHello(ctx, &pb.HelloRequest{Name: *serverAddr})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Greeting: %s", r.GetMessage())
}
