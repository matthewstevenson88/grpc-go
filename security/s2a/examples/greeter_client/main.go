/*
 *
 * Copyright 2015 gRPC authors.
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

// Package main implements a client for Greeter service.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	pb "google.golang.org/grpc/security/s2a/examples/helloworld"
)

const (
	port        = "50051"
	defaultName = "world"
)

func main() {
	if len(os.Args) != 5 {
		log.Fatalf("Invalid number of arguments provided: %v", len(os.Args))
	}
	address := os.Args[1]
	rootCert := os.Args[2]
	certFile := os.Args[3]
	keyFile := os.Args[4]

	certificate, err := tls.LoadX509KeyPair(
		certFile,
		keyFile,
	)
	if err != nil {
		log.Fatalf("Failed to setup TLS certificate: %v", err)
	}

	// Load root certs.
	certPool := x509.NewCertPool()
	clientPem, err := ioutil.ReadFile(rootCert)
	if err != nil {
		log.Fatalf("Failed to read client pem: %s", err)
	}
	ok := certPool.AppendCertsFromPEM(clientPem)
	if !ok {
		log.Fatal("Failed to append client pem")
	}

	// Set up TLS config.
	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS13,
	}

	// Set up a connection to the server.
	fullAddress := address + ":" + port
	conn, err := grpc.Dial(fullAddress, grpc.WithTransportCredentials(credentials.NewTLS(config)), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewGreeterClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.SayHello(ctx, &pb.HelloRequest{Name: address})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Greeting: %s", r.GetMessage())
}
