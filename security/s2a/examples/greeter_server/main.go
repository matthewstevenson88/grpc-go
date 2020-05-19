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

// Package main implements a server for Greeter service.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"log"
	"net"

	"google.golang.org/grpc"
	pb "google.golang.org/grpc/security/s2a/examples/helloworld"
)

var (
	port     = flag.String("port", "50051", "port number to use for connection")
	rootCert = flag.String("client_root_cert_pem_path", "../../testdata/ca.cert", "path to root X509 certificate")
	certFile = flag.String("server_cert_pem_path", "../../testdata/service.pem", "path to server's X509 certificate")
	keyFile  = flag.String("server_key_pem_path", "../../testdata/service.key", "path to server's private key")
)

// server is used to implement helloworld.GreeterServer.
type server struct {
	pb.UnimplementedGreeterServer
}

// SayHello implements helloworld.GreeterServer
func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	log.Printf("Received: %v", in.GetName())
	return &pb.HelloReply{Message: "Hello " + in.GetName()}, nil
}

func main() {
	flag.Parse()

	// Load TLS keys.
	certificate, err := tls.LoadX509KeyPair(
		*certFile,
		*keyFile,
	)
	if err != nil {
		log.Fatalf("failed to load server's X509 certificate: %v", err)
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
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	creds := credentials.NewTLS(config)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %s: %v", *port, err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
