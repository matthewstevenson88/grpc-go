// Copyright 2020 The gRPC Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.15.8
// source: grpc/lookup/v1/rls.proto

package grpc_lookup_v1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	RouteLookupService_RouteLookup_FullMethodName = "/grpc.lookup.v1.RouteLookupService/RouteLookup"
)

// RouteLookupServiceClient is the client API for RouteLookupService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type RouteLookupServiceClient interface {
	// Lookup returns a target for a single key.
	RouteLookup(ctx context.Context, in *RouteLookupRequest, opts ...grpc.CallOption) (*RouteLookupResponse, error)
}

type routeLookupServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewRouteLookupServiceClient(cc grpc.ClientConnInterface) RouteLookupServiceClient {
	return &routeLookupServiceClient{cc}
}

func (c *routeLookupServiceClient) RouteLookup(ctx context.Context, in *RouteLookupRequest, opts ...grpc.CallOption) (*RouteLookupResponse, error) {
	out := new(RouteLookupResponse)
	err := c.cc.Invoke(ctx, RouteLookupService_RouteLookup_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RouteLookupServiceServer is the server API for RouteLookupService service.
// All implementations must embed UnimplementedRouteLookupServiceServer
// for forward compatibility
type RouteLookupServiceServer interface {
	// Lookup returns a target for a single key.
	RouteLookup(context.Context, *RouteLookupRequest) (*RouteLookupResponse, error)
	mustEmbedUnimplementedRouteLookupServiceServer()
}

// UnimplementedRouteLookupServiceServer must be embedded to have forward compatible implementations.
type UnimplementedRouteLookupServiceServer struct {
}

func (UnimplementedRouteLookupServiceServer) RouteLookup(context.Context, *RouteLookupRequest) (*RouteLookupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RouteLookup not implemented")
}
func (UnimplementedRouteLookupServiceServer) mustEmbedUnimplementedRouteLookupServiceServer() {}

// UnsafeRouteLookupServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to RouteLookupServiceServer will
// result in compilation errors.
type UnsafeRouteLookupServiceServer interface {
	mustEmbedUnimplementedRouteLookupServiceServer()
}

func RegisterRouteLookupServiceServer(s grpc.ServiceRegistrar, srv RouteLookupServiceServer) {
	s.RegisterService(&RouteLookupService_ServiceDesc, srv)
}

func _RouteLookupService_RouteLookup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RouteLookupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RouteLookupServiceServer).RouteLookup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RouteLookupService_RouteLookup_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RouteLookupServiceServer).RouteLookup(ctx, req.(*RouteLookupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// RouteLookupService_ServiceDesc is the grpc.ServiceDesc for RouteLookupService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var RouteLookupService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "grpc.lookup.v1.RouteLookupService",
	HandlerType: (*RouteLookupServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "RouteLookup",
			Handler:    _RouteLookupService_RouteLookup_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "grpc/lookup/v1/rls.proto",
}
