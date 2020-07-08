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

package service

import (
	"testing"

	grpc "google.golang.org/grpc"
)

const (
	// The address is irrelevant in this test.
	testAddress  = "some_address"
	testAddress2 = "some_address2"
)

func TestDial(t *testing.T) {
	defer func() func() {
		temp := hsDialer
		hsDialer = func(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
			return &grpc.ClientConn{}, nil
		}
		return func() {
			hsDialer = temp
		}
	}()

	// First call to Dial, it should create a connection for the given address.
	conn1, err := Dial(testAddress)
	if err != nil {
		t.Fatalf("first call to Dial(%v) failed: %v", testAddress, err)
	}
	if conn1 == nil {
		t.Fatalf("first call to Dial(%v)=(nil, _), want not nil", testAddress)
	}
	if got, want := hsConnMap[testAddress], conn1; got != want {
		t.Fatalf("hsConnmap[%v] = %v, want %v", testAddress, got, want)
	}

	// Second call to Dial should return conn1 above.
	conn2, err := Dial(testAddress)
	if err != nil {
		t.Fatalf("second call to Dial(%v) failed: %v", testAddress, err)
	}
	if got, want := conn2, conn1; got != want {
		t.Fatalf("second call to Dial(%v)=(%v, _), want (%v, _)", testAddress, got, want)
	}
	if got, want := hsConnMap[testAddress], conn1; got != want {
		t.Fatalf("hsConnMap[%v] = %v, want %v", testAddress, got, want)
	}

	// Third call to Dial using a different address should create a new
	// connection.
	conn3, err := Dial(testAddress2)
	if err != nil {
		t.Fatalf("third call to Dial(%v) failed: %v", testAddress2, err)
	}
	if conn3 == nil {
		t.Fatalf("third call to Dial(%v)=(nil, _), want not nil", testAddress)
	}
	if got, want := hsConnMap[testAddress2], conn3; got != want {
		t.Fatalf("hsConnmap[%v] = %v, want %v", testAddress2, got, want)
	}
	if got, want := conn2 == conn3, false; got != want {
		t.Fatalf("(conn2 == conn3) = %v, want %v", got, want)
	}
}
