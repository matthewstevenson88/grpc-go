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
	"sync"

	grpc "google.golang.org/grpc"
)

var (
	// hsConn represents a connection to the S2A  handshaker service.
	hsConn    *grpc.ClientConn
	hsAddress string
	// mu guards hsDialer
	mu sync.Mutex
	// hsDialer will be reassigned in tests.
	hsDialer = grpc.Dial
)

// Dial dials the S2A handshaker service. If a connection has already been
// established, this function returns it. Otherwise, a new connection is
// created.
func Dial(handshakerServiceAddress string) (*grpc.ClientConn, error) {
	mu.Lock()
	defer mu.Unlock()

	if hsConn == nil {
		// Create a new connection to the S2A handshaker service. Note that
		// this connection stays open until the application is closed.
		var err error
		hsAddress = handshakerServiceAddress
		hsConn, err = hsDialer(handshakerServiceAddress, grpc.WithInsecure())
		if err != nil {
			return nil, err
		}
	}
	return hsConn, nil
}
