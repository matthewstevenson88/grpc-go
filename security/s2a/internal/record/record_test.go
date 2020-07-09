package record

import (
	"bytes"
	"errors"
	"net"
	"testing"

	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
	"google.golang.org/grpc/security/s2a/internal/record/internal/aeadcrypter/testutil"
)

// fakeConn is a fake implementation of the net.Conn interface used for testing.
type fakeConn struct {
	net.Conn
	// inCount tracks the current index of the `in` buffer.
	inCount int
	in, out [][]byte
	closed  bool
}

// Read returns part of the `in` buffer in sequential order each time it is
// called.
func (c *fakeConn) Read(b []byte) (n int, err error) {
	n = copy(b, c.in[c.inCount])
	if n < len(c.in[c.inCount]) {
		// For testing, we want to make sure that each buffer is copied in its
		// entirety.
		return 0, errors.New("copy copied less bytes than expected")
	}
	c.inCount++
	return n, nil
}

// Write copies the given buffer b, stores it in the `out` buffer, and returns
// the number of bytes copied.
func (c *fakeConn) Write(b []byte) (n int, err error) {
	outBuf := make([]byte, len(b))
	n = copy(outBuf, b)
	c.out = append(c.out, outBuf)
	return n, nil
}

func (c *fakeConn) Close() error {
	c.closed = true
	return nil
}

func TestNewS2ARecordConn(t *testing.T) {
	for _, tc := range []struct {
		desc                     string
		options                  *ConnParameters
		outUnusedBytesBuf        []byte
		outOverheadSize          int
		outHandshakerServiceAddr string
		outErr                   bool
	}{
		{
			desc:   "nil conn options",
			outErr: true,
		},
		{
			desc: "invalid input traffic secret size",
			options: &ConnParameters{
				NetConn:          &fakeConn{},
				Ciphersuite:      s2apb.Ciphersuite_AES_256_GCM_SHA384,
				TLSVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				OutTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				HsAddr:           "test handshaker address",
			},
			outErr: true,
		},
		{
			desc: "invalid output traffic secret size",
			options: &ConnParameters{
				NetConn:          &fakeConn{},
				Ciphersuite:      s2apb.Ciphersuite_AES_256_GCM_SHA384,
				TLSVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				OutTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				HsAddr:           "test handshaker address",
			},
			outErr: true,
		},
		{
			desc: "invalid tls version",
			options: &ConnParameters{
				NetConn:          &fakeConn{},
				Ciphersuite:      s2apb.Ciphersuite_AES_128_GCM_SHA256,
				TLSVersion:       s2apb.TLSVersion_TLS1_2,
				InTrafficSecret:  testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				OutTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				HsAddr:           "test handshaker address",
			},
			outErr: true,
		},
		{
			desc: "basic with AES-128-GCM-SHA256",
			options: &ConnParameters{
				NetConn:          &fakeConn{},
				Ciphersuite:      s2apb.Ciphersuite_AES_128_GCM_SHA256,
				TLSVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				OutTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				HsAddr:           "test handshaker address",
			},
			// outOverheadSize = header size (5) + record type byte (1) +
			// tag size (16).
			outOverheadSize:          22,
			outHandshakerServiceAddr: "test handshaker address",
		},
		{
			desc: "basic with AES-256-GCM-SHA384",
			options: &ConnParameters{
				NetConn:          &fakeConn{},
				Ciphersuite:      s2apb.Ciphersuite_AES_256_GCM_SHA384,
				TLSVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				OutTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				HsAddr:           "test handshaker address",
			},
			// outOverheadSize = header size (5) + record type byte (1) +
			// tag size (16).
			outOverheadSize:          22,
			outHandshakerServiceAddr: "test handshaker address",
		},
		{
			desc: "basic with CHACHA20-POLY1305-SHA256",
			options: &ConnParameters{
				NetConn:          &fakeConn{},
				Ciphersuite:      s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
				TLSVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				OutTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				HsAddr:           "test handshaker address",
			},
			// outOverheadSize = header size (5) + record type byte (1) +
			// tag size (16).
			outOverheadSize:          22,
			outHandshakerServiceAddr: "test handshaker address",
		},
		{
			desc: "basic with unusedBytes",
			options: &ConnParameters{
				NetConn:          &fakeConn{},
				Ciphersuite:      s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
				TLSVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				OutTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
				UnusedBuf:        testutil.Dehex("ffffffff"),
				HsAddr:           "test handshaker address",
			},
			outUnusedBytesBuf: testutil.Dehex("ffffffff"),
			// outOverheadSize = header size (5) + record type byte (1) +
			// tag size (16).
			outOverheadSize:          22,
			outHandshakerServiceAddr: "test handshaker address",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			NetConn, err := NewConn(tc.options)
			if got, want := err == nil, !tc.outErr; got != want {
				t.Errorf("NewConn(%v) = (err=nil) = %v, want %v", *tc.options, got, want)
			}
			if err != nil {
				return
			}
			conn := NetConn.(*conn)
			if got, want := conn.unusedBuf, tc.outUnusedBytesBuf; !bytes.Equal(got, want) {
				t.Errorf("conn.unusedBytes = %v, want %v", got, want)
			}
			if got, want := conn.overheadSize, tc.outOverheadSize; got != want {
				t.Errorf("conn.overheadSize = %v, want %v", got, want)
			}
			if got, want := conn.hsAddr, tc.outHandshakerServiceAddr; got != want {
				t.Errorf("conn.HsAddr = %v, want %v", got, want)
			}
		})
	}
}

func TestConnRead(t *testing.T) {
	conn := &conn{}
	if _, err := conn.Read(nil); err == nil {
		t.Errorf("read is unimplemented")
	}
}

func TestBuildHeader(t *testing.T) {
	payload := make([]byte, 0)
	expectedHeader := []byte{23, 3, 3, 0, 17}
	resultHeader, err := buildHeader(payload, tlsApplicationData)
	if !bytes.Equal(expectedHeader, resultHeader) {
		t.Errorf("Incorrect Header: Expected: %v, Received: %v", expectedHeader, resultHeader)
	}
	if err != nil {
		t.Errorf("buildHeader returned error: %v", err)
	}
	payload = make([]byte, 6)
	expectedHeader = []byte{23, 3, 3, 0, 23}
	resultHeader, err = buildHeader(payload, tlsApplicationData)
	if !bytes.Equal(expectedHeader, resultHeader) {
		t.Errorf("Incorrect Header: Expected: %v, Received: %v", expectedHeader, resultHeader)
	}
	if err != nil {
		t.Errorf("buildHeader returned error: %v", err)
	}
	payload = make([]byte, 256)
	expectedHeader = []byte{23, 3, 3, 1, 17}
	resultHeader, err = buildHeader(payload, tlsApplicationData)
	if !bytes.Equal(expectedHeader, resultHeader) {
		t.Errorf("Incorrect Header: Expected: %v, Received: %v", expectedHeader, resultHeader)
	}
	if err != nil {
		t.Errorf("buildHeader returned error: %v", err)
	}
	payload = make([]byte, tlsRecordMaxPlaintextSize+1)
	resultHeader, err = buildHeader(payload, tlsApplicationData)
	if resultHeader != nil || err == nil {
		t.Errorf("Expected error, got: %v, %v", resultHeader, err)
	}

}

func TestConnWrite(t *testing.T) {
	for _, tc := range []struct {
		desc             string
		ciphersuite      s2apb.Ciphersuite
		trafficSecret []byte
		records          [][]byte
		inPlaintexts     [][]byte
		outErr           bool
	}{
		// The traffic secrets were chosen randomly and are equivalent to the
		// ones used in C++ and Java. The ciphertext was constructed using an
		// existing TLS library.
		{
			desc:             "AES-128-GCM-SHA256 with no padding",
			ciphersuite:      s2apb.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("1703030017f2e4e411ac6760e4e3f074a36574c45ee4c1906103db0d"),
				testutil.Dehex("170303001ad7853afd6d7ceaabab950a0b6707905d2b908894871c7c62021f"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:             "AES-128-GCM-SHA256 with padding",
			ciphersuite:      s2apb.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("1703030021f2e4e411ac6760e84726e4886d7432e39b34f0fccfc1f4558303c68a19535c0ff5"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:             "AES-128-GCM-SHA256 empty",
			ciphersuite:      s2apb.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("1703030011d47cb2ec040f26cc8989330339c669dd4e"),
			},
			inPlaintexts: [][]byte{
				[]byte(""),
			},
		},
		{
			desc:             "AES-256-GCM-SHA384 with no padding",
			ciphersuite:      s2apb.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("170303001724efee5af1a62170ad5a95f899d038b965386a1a7daed9"),
				testutil.Dehex("170303001a832a5fd271b6442e74bc02111a8e8b52a74b14dd3eca8598b293"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:             "AES-256-GCM-SHA384 with padding",
			ciphersuite:      s2apb.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("170303002124efee5af1a621e8a4d1f269930e7835cfdd05e2d0bec5b01a67decfa6372c2af7"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:             "AES-256-GCM-SHA384 empty",
			ciphersuite:      s2apb.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("170303001102a04134d38c1118f36b01d177c5d2dcf7"),
			},
			inPlaintexts: [][]byte{
				[]byte(""),
			},
		},
		{
			desc:             "CHACHA20-POLY1305-SHA256 with no padding",
			ciphersuite:      s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("1703030017c947ffa470304370338bb07ce468e6b8a0944a338ba402"),
				testutil.Dehex("170303001a0cedeb922170c110c172262542c67916b78fa0d1c1261709cd00"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:             "CHACHA20-POLY1305-SHA256 with padding",
			ciphersuite:      s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("1703030021c947ffa4703043f063e7b6a0519fbd0956cf3a7c9730c13597eec17ec7e700f140"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:             "CHACHA20-POLY1305-SHA256 empty",
			ciphersuite:      s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("1703030011ef8f7a428ddc84ee5968cd6306bf1d2d1b"),
			},
			inPlaintexts: [][]byte{
				[]byte(""),
			},
		},
		{
			desc:             "AES-128-GCM-SHA256 split in first record",
			ciphersuite:      s2apb.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("1703030017f2e4e411ac6760"),
				testutil.Dehex("e4e3f074a36574c45ee4c1906103db0d"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:             "AES-256-GCM-SHA384 split in first record",
			ciphersuite:      s2apb.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("170303001724efee5af1a6"),
				testutil.Dehex("2170ad5a95f899d038b965386a1a7daed9"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:             "CHACHA20-POLY1305-SHA256 split in first record",
			ciphersuite:      s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("1703030017c947ffa470"),
				testutil.Dehex("304370338bb07ce468e6b8a0944a338ba402"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:             "AES-128-GCM-SHA256 split in first record header",
			ciphersuite:      s2apb.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("17"),
				testutil.Dehex("03030017f2e4e411ac6760e4e3f074a36574c45ee4c1906103db0d"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:             "AES-256-GCM-SHA384 split in first record header",
			ciphersuite:      s2apb.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("17"),
				testutil.Dehex("0303001724efee5af1a62170ad5a95f899d038b965386a1a7daed9"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:             "CHACHA20-POLY1305-SHA256 split in first record header",
			ciphersuite:      s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("17"),
				testutil.Dehex("03030017c947ffa470304370338bb07ce468e6b8a0944a338ba402"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:             "AES-128-GCM-SHA256 split in second record",
			ciphersuite:      s2apb.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("1703030017f2e4e411ac6760e4e3f074a36574c45ee4c1906103db0d170303001ad7"),
				testutil.Dehex("853afd6d7ceaabab950a0b6707905d2b908894871c7c62021f"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:             "AES-256-GCM-SHA384 split in second record",
			ciphersuite:      s2apb.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("170303001724efee5af1a62170ad5a95f899d038b965386a1a7daed9170303001a83"),
				testutil.Dehex("2a5fd271b6442e74bc02111a8e8b52a74b14dd3eca8598b293"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:             "CHACHA20-POLY1305-SHA256 split in second record",
			ciphersuite:      s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("1703030017c947ffa470304370338bb07ce468e6b8a0944a338ba402170303001a0c"),
				testutil.Dehex("edeb922170c110c172262542c67916b78fa0d1c1261709cd00"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:             "AES-128-GCM-SHA256 split in second record header",
			ciphersuite:      s2apb.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("1703030017f2e4e411ac6760e4e3f074a36574c45ee4c1906103db0d17"),
				testutil.Dehex("0303001ad7853afd6d7ceaabab950a0b6707905d2b908894871c7c62021f"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:             "AES-256-GCM-SHA384 split in second record header",
			ciphersuite:      s2apb.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("170303001724efee5af1a62170ad5a95f899d038b965386a1a7daed917"),
				testutil.Dehex("0303001a832a5fd271b6442e74bc02111a8e8b52a74b14dd3eca8598b293"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:             "CHACHA20-POLY1305-SHA256 split in second record header",
			ciphersuite:      s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("1703030017c947ffa470304370338bb07ce468e6b8a0944a338ba40217"),
				testutil.Dehex("0303001a0cedeb922170c110c172262542c67916b78fa0d1c1261709cd00"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:             "AES-128-GCM-SHA256 split randomly",
			ciphersuite:      s2apb.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("1703030017f2e4e411ac6760e4"),
				testutil.Dehex("e3f074a36574c45ee4c1906103db0d17"),
				testutil.Dehex("0303001ad7853afd6d7ceaab"),
				testutil.Dehex("ab950a0b6707905d2b908894871c7c62021f"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:             "AES-256-GCM-SHA384 split randomly",
			ciphersuite:      s2apb.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("170303001724efee"),
				testutil.Dehex("5af1a62170ad5a95f899d038b965386a1a7daed917"),
				testutil.Dehex("03"),
				testutil.Dehex("03001a832a5fd271b6442e74bc02111a8e8b52a74b14dd3eca8598b293"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:             "CHACHA20-POLY1305-SHA256 split randomly",
			ciphersuite:      s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			records: [][]byte{
				testutil.Dehex("17"),
				testutil.Dehex("03030017c947ffa470304370338bb07ce468e6b8a0944a338ba40217"),
				testutil.Dehex("0303001a0cedeb922170"),
				testutil.Dehex("c110c172262542c67916b78fa0d1c1261709cd00"),
			},
			inPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			c, err := NewConn(&ConnParameters{
				NetConn:          &fakeConn{in: tc.records},
				Ciphersuite:      tc.ciphersuite,
				TLSVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  tc.trafficSecret,
				OutTrafficSecret: tc.trafficSecret,
			})
			if err != nil {
				t.Fatalf("NewConn() failed: %v", err)
			}
			for _, inPlaintext := range tc.inPlaintexts {
				n, err := c.Write(inPlaintext)
				if got, want := err == nil, !tc.outErr; got != want {
					t.Errorf("c.Write(plaintext) = (err=nil) = %v, want %v", got, want)
				}
				if n != len(inPlaintext) {
					t.Errorf("Wrote %v bytes, expected %v", n, len(inPlaintext))
				}
			}
		})
	}
}
