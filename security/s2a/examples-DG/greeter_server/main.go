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

// Package main implements a server for Greeter service.
package main

import (
	"context"
	"log"
	"net"

	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"google.golang.org/grpc/credentials"

	"google.golang.org/grpc"
	pb "google.golang.org/grpc/examples/helloworld/helloworld"
)

const (
	port = ":50051"
	ca = "../../testdata/ca.cert"
	cert = "../../testdata/service.pem"
	key = "../../testdata/service.key"
	minVersion = tls.VersionTLS13
	maxVersion = tls.VersionTLS13
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
	// Load certificates from disk
	certificate, err := tls.LoadX509KeyPair(cert,key)
	if err != nil {
		log.Fatalf("could not load server key pair: %s",err)
	}

	//Create a certificate pool from the certificate authority
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(ca)
	if err != nil {
		log.Fatalf("could not read ca certificate; %s",err)
	}

	//Append the client certificates from the CA
	if ok:= certPool.AppendCertsFromPEM(ca); !ok {
		log.Fatalf("failed to append client certs")
	}

	//Create a channel to listen on thru given port
	lis, err := net.Listen("tcp",port)
	if err != nil {
		log.Fatalf("failed to listen: %s", err)
	}

	//Create the TLS credentials
	creds := credentials.NewTLS(&tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:certPool,
		MinVersion: minVersion,
		MaxVersion: maxVersion,
		})

	//Create the gRPC server with the credentials
	srv := grpc.NewServer(grpc.Creds(creds))

	//Register the handler object
	pb.RegisterGreeterServer(srv, &server{})

	//Serve and Listen
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}
