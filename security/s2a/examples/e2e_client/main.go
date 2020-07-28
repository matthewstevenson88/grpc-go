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
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/security/s2a"
	pb "google.golang.org/grpc/security/s2a/examples/helloworld"
)

var (
	serverAddr    = flag.String("server_address", "localhost:50051", "The address of the gRPC server.")
	s2aServerAddr = flag.String("s2a_server_address", "localhost:61365", "S2A server address.")
)

func main() {
	flag.Parse()

	// Set up the client-side S2A transport credentials.
	clientOpts := &s2a.ClientOptions{
		HandshakerServiceAddress: *s2aServerAddr,
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
	r, err := c.SayHello(ctx, &pb.HelloRequest{Name: "S2A team"})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	if r.String() != "Hello, S2A team!" {
		os.Exit(1)
	}
	log.Printf("Greeting: %s", r.GetMessage())
}
