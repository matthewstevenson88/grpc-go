/*
 *
 * Copyright 2023 gRPC authors.
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

package envconfig

const (
	// ALTSMaxConcurrentHandshakesEnv is the env variable to set the
	// maximum number of concurrent ALTS handshakes that can be performed.
	// Its value is read and kept in the variable
	// ALTSMaxConcurrentHandshakes.
	ALTSMaxConcurrentHandshakesEnv     = "GRPC_ALTS_MAX_CONCURRENT_HANDSHAKES"
	altsDefaultMaxConcurrentHandshakes = uint64(100)
)

var (
	// ALTSMaxConcurrentHandshakes is the maximum number of concurrent ALTS
	// handshakes that can be performed.
	ALTSMaxConcurrentHandshakes = uint64FromEnv(ALTSMaxConcurrentHandshakesEnv, altsDefaultMaxConcurrentHandshakes, uint64(1), altsDefaultMaxConcurrentHandshakes)
)