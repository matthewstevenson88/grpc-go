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

// Package main implements a client for Greeter service.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"log"
	"time"

	"google.golang.org/grpc"
	pb "google.golang.org/grpc/security/s2a/examples/helloworld"
)

var (
	serverAddr = flag.String("server_address", "localhost:50051", "address of the server")
	rootCert   = flag.String("server_root_cert_pem_path", "../../testdata/ca.cert", "path to root X509 certificate")
	certFile   = flag.String("client_cert_pem_path", "../../testdata/client.pem", "path to client's X509 certificate")
	keyFile    = flag.String("client_key_pem_path", "../../testdata/client.key", "path to client's private key")
)

func main() {
	flag.Parse()

	certificate, err := tls.LoadX509KeyPair(
		*certFile,
		*keyFile,
	)
	if err != nil {
		log.Fatalf("failed to load client's X509 certificate: %v", err)
	}

	// Load root certs.
	certPool := x509.NewCertPool()
	rootPem, err := ioutil.ReadFile(*rootCert)
	if err != nil {
		log.Fatalf("failed to read root pem: %s", err)
	}
	ok := certPool.AppendCertsFromPEM(rootPem)
	if !ok {
		log.Fatal("failed to append root pem")
	}

	// Set up TLS config.
	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	// Set up a connection to the server.
	conn, err := grpc.Dial(*serverAddr, grpc.WithTransportCredentials(credentials.NewTLS(config)), grpc.WithBlock())
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
