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
	inCount, outCount int
	in, out           [][]byte
}

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

func (c *fakeConn) Write(b []byte) (n int, err error) {
	outBuf := make([]byte, len(b))
	n = copy(outBuf, b)
	c.out = append(c.out, outBuf)
	return n, nil
}

func (c *fakeConn) Close() error { return nil }

func TestNewS2ARecordConn(t *testing.T) {
	for _, tc := range []struct {
		desc                     string
		options                  *ConnOptions
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
			options: &ConnOptions{
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
			options: &ConnOptions{
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
			options: &ConnOptions{
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
			options: &ConnOptions{
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
			options: &ConnOptions{
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
			options: &ConnOptions{
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
			options: &ConnOptions{
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

func TestStripPaddingAndType(t *testing.T) {
	for _, tc := range []struct {
		desc                                              string
		pendingApplicationData, outPendingApplicationData []byte
		outContentType                                    contentType
	}{
		{
			desc:                   "no padding",
			pendingApplicationData: []byte{byte(alert)},
			outContentType:         alert,
		},
		{
			desc:                   "single padding",
			pendingApplicationData: []byte{byte(applicationData), 0x00},
			outContentType:         applicationData,
		},
		{
			desc:                   "multi padding",
			pendingApplicationData: []byte{byte(handshake), 0x00, 0x00},
			outContentType:         handshake,
		},
		{
			desc:                      "app data with no padding",
			pendingApplicationData:    []byte{0xff, byte(handshake)},
			outPendingApplicationData: []byte{0xff},
			outContentType:            handshake,
		},
		{
			desc:                      "app data with padding",
			pendingApplicationData:    []byte{0xff, byte(handshake), 0x00},
			outPendingApplicationData: []byte{0xff},
			outContentType:            handshake,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			c := conn{pendingApplicationData: tc.pendingApplicationData}
			ct := c.stripPaddingAndType()
			if got, want := c.pendingApplicationData, tc.outPendingApplicationData; !bytes.Equal(got, want) {
				t.Errorf("c.pendingApplicationData = %v, want %v", got, want)
			}
			if got, want := ct, tc.outContentType; got != want {
				t.Errorf("ct = %v, want %v", got, want)
			}
		})
	}
}

func TestParseRecord(t *testing.T) {
	for _, tc := range []struct {
		desc                             string
		b                                []byte
		maxLen                           uint16
		outCompletedRecord, outRemaining []byte
		outErr                           bool
	}{
		{
			desc:         "buffer smaller than header size",
			b:            make([]byte, 1),
			outRemaining: make([]byte, 1),
		},
		{
			desc:         "header payload size larger than maxLen",
			b:            testutil.Dehex("000000ffff"),
			maxLen:       1,
			outRemaining: testutil.Dehex("000000ffff"),
			outErr:       true,
		},
		{
			desc:         "incomplete record",
			b:            testutil.Dehex("0000000001"),
			maxLen:       10,
			outRemaining: testutil.Dehex("0000000001"),
		},
		{
			desc:               "complete record",
			b:                  testutil.Dehex("0000000001ff"),
			maxLen:             10,
			outCompletedRecord: testutil.Dehex("0000000001ff"),
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			completedRecord, remaining, err := parseRecord(tc.b, tc.maxLen)
			if got, want := err == nil, !tc.outErr; got != want {
				t.Errorf("parseRecord(%v, %v) = (err=nil) = %v, want %v", tc.b, tc.maxLen, got, want)
			}
			if err != nil {
				return
			}
			if got, want := completedRecord, tc.outCompletedRecord; !bytes.Equal(got, want) {
				t.Errorf("completedRecord = %v, want %v", got, want)
			}
			if got, want := remaining, tc.outRemaining; !bytes.Equal(got, want) {
				t.Errorf("remaining = %v, want %v", got, want)
			}
		})
	}
}

func TestReadCompletedRecord(t *testing.T) {
	for _, tc := range []struct {
		desc                  string
		connBufs              [][]byte
		nextRecord, unusedBuf []byte
		outCompletedRecords   [][]byte
		outErr                bool
	}{
		{
			desc:       "invalid record header size",
			nextRecord: testutil.Dehex("170303ffff"),
			outErr:     true,
		},
		{
			desc: "complete record in single read",
			connBufs: [][]byte{
				testutil.Dehex("1703030001ff"),
			},
			outCompletedRecords: [][]byte{
				testutil.Dehex("1703030001ff"),
			},
		},
		{
			desc:       "complete record in single read from leftover buffer",
			nextRecord: testutil.Dehex("1703030001ff"),
			outCompletedRecords: [][]byte{
				testutil.Dehex("1703030001ff"),
			},
		},
		{
			desc: "complete record split in header",
			connBufs: [][]byte{
				testutil.Dehex("170303"),
				testutil.Dehex("0001ff"),
			},
			unusedBuf: make([]byte, tlsRecordMaxPlaintextSize),
			outCompletedRecords: [][]byte{
				testutil.Dehex("1703030001ff"),
			},
		},
		{
			desc: "complete record split in ciphertext",
			connBufs: [][]byte{
				testutil.Dehex("1703030002ff"),
				testutil.Dehex("ff"),
			},
			unusedBuf: make([]byte, tlsRecordMaxPlaintextSize),
			outCompletedRecords: [][]byte{
				testutil.Dehex("1703030002ffff"),
			},
		},
		{
			desc: "two complete records split in header",
			connBufs: [][]byte{
				testutil.Dehex("170303"),
				testutil.Dehex("0002ffff1703030001ff"),
			},
			unusedBuf: make([]byte, tlsRecordMaxPlaintextSize),
			outCompletedRecords: [][]byte{
				testutil.Dehex("1703030002ffff"),
				testutil.Dehex("1703030001ff"),
			},
		},
		{
			desc: "two complete records split in second header",
			connBufs: [][]byte{
				testutil.Dehex("1703030002ffff1703"),
				testutil.Dehex("030001ff"),
			},
			unusedBuf: make([]byte, tlsRecordMaxPlaintextSize),
			outCompletedRecords: [][]byte{
				testutil.Dehex("1703030002ffff"),
				testutil.Dehex("1703030001ff"),
			},
		},
		{
			desc: "two complete records split in ciphertext",
			connBufs: [][]byte{
				testutil.Dehex("1703030002ff"),
				testutil.Dehex("ff1703030001ff"),
			},
			unusedBuf: make([]byte, tlsRecordMaxPlaintextSize),
			outCompletedRecords: [][]byte{
				testutil.Dehex("1703030002ffff"),
				testutil.Dehex("1703030001ff"),
			},
		},
		{
			desc: "two complete records split in second ciphertext",
			connBufs: [][]byte{
				testutil.Dehex("1703030002ffff1703030002ff"),
				testutil.Dehex("ff"),
			},
			unusedBuf: make([]byte, tlsRecordMaxPlaintextSize),
			outCompletedRecords: [][]byte{
				testutil.Dehex("1703030002ffff"),
				testutil.Dehex("1703030002ffff"),
			},
		},
		{
			desc: "complete record split by each byte",
			connBufs: [][]byte{
				{0x17}, {0x03}, {0x03}, {0x00}, {0x01}, {0xff},
			},
			unusedBuf: make([]byte, tlsRecordMaxPlaintextSize),
			outCompletedRecords: [][]byte{
				testutil.Dehex("1703030001ff"),
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			fc := &fakeConn{in: tc.connBufs}
			c := &conn{Conn: fc, nextRecord: tc.nextRecord, unusedBuf: tc.unusedBuf}
			for _, outCompletedRecord := range tc.outCompletedRecords {
				completedRecord, err := c.readCompletedRecord()
				if got, want := err == nil, !tc.outErr; got != want {
					t.Errorf("c.readCompletecRecord() = (err=nil) = %v, want %v", got, want)
				}
				if err != nil {
					return
				}
				if got, want := completedRecord, outCompletedRecord; !bytes.Equal(got, want) {
					t.Errorf("c.readCompletedRecord() = %v, want %v", got, want)
				}
			}
		})
	}
}

func TestSplitAndValidateHeader(t *testing.T) {
	for _, tc := range []struct {
		desc                     string
		completedRecord          []byte
		outHeader, outCiphertext []byte
		outErr                   bool
	}{
		{
			desc:            "invalid header type",
			completedRecord: make([]byte, tlsRecordHeaderSize),
			outErr:          true,
		},
		{
			desc:            "invalid legacy record version",
			completedRecord: []byte{byte(tlsApplicationData), 0x00, 0x00, 0x00, 0x00},
			outErr:          true,
		},
		{
			desc:            "basic with no ciphertext",
			completedRecord: []byte{byte(tlsApplicationData), 0x03, 0x03, 0x00, 0x00},
			outHeader:       []byte{byte(tlsApplicationData), 0x03, 0x03, 0x00, 0x00},
		},
		{
			desc:            "basic with ciphertext",
			completedRecord: []byte{byte(tlsApplicationData), 0x03, 0x03, 0x00, 0x01, 0xff},
			outHeader:       []byte{byte(tlsApplicationData), 0x03, 0x03, 0x00, 0x01},
			outCiphertext:   []byte{0xff},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			header, ciphertext, err := splitAndValidateHeader(tc.completedRecord)
			if got, want := err == nil, !tc.outErr; got != want {
				t.Errorf("splitAndValidateHeader(%v) = (err=nil) = %v, want %v", tc.completedRecord, got, want)
			}
			if err != nil {
				return
			}
			if got, want := header, tc.outHeader; !bytes.Equal(got, want) {
				t.Errorf("header = %v, want %v", got, want)
			}
			if got, want := ciphertext, tc.outCiphertext; !bytes.Equal(got, want) {
				t.Errorf("ciphertext = %v, want %v", got, want)
			}
		})
	}
}

func TestConnReadApplicationData(t *testing.T) {
	for _, tc := range []struct {
		desc             string
		ciphersuite      s2apb.Ciphersuite
		inTrafficSecret  []byte
		completedRecords [][]byte
		outPlaintexts    [][]byte
		outErr           bool
	}{
		// The traffic secrets were chosen randomly and are equivalent to the
		// ones used in C++ and Java. The ciphertext was constructed using an
		// existing TLS library.
		{
			desc:            "AES-128-GCM-SHA256 with no padding",
			ciphersuite:     s2apb.Ciphersuite_AES_128_GCM_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("1703030017f2e4e411ac6760e4e3f074a36574c45ee4c1906103db0d"),
				testutil.Dehex("170303001ad7853afd6d7ceaabab950a0b6707905d2b908894871c7c62021f"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:            "AES-128-GCM-SHA256 with padding",
			ciphersuite:     s2apb.Ciphersuite_AES_128_GCM_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("1703030021f2e4e411ac6760e84726e4886d7432e39b34f0fccfc1f4558303c68a19535c0ff5"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:            "AES-128-GCM-SHA256 empty",
			ciphersuite:     s2apb.Ciphersuite_AES_128_GCM_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("1703030011d47cb2ec040f26cc8989330339c669dd4e"),
			},
			outPlaintexts: [][]byte{
				[]byte(""),
			},
		},
		{
			desc:            "AES-256-GCM-SHA384 with no padding",
			ciphersuite:     s2apb.Ciphersuite_AES_256_GCM_SHA384,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("170303001724efee5af1a62170ad5a95f899d038b965386a1a7daed9"),
				testutil.Dehex("170303001a832a5fd271b6442e74bc02111a8e8b52a74b14dd3eca8598b293"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:            "AES-256-GCM-SHA384 with padding",
			ciphersuite:     s2apb.Ciphersuite_AES_256_GCM_SHA384,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("170303002124efee5af1a621e8a4d1f269930e7835cfdd05e2d0bec5b01a67decfa6372c2af7"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:            "AES-256-GCM-SHA384 empty",
			ciphersuite:     s2apb.Ciphersuite_AES_256_GCM_SHA384,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("170303001102a04134d38c1118f36b01d177c5d2dcf7"),
			},
			outPlaintexts: [][]byte{
				[]byte(""),
			},
		},
		{
			desc:            "CHACHA20-POLY1305-SHA256 with no padding",
			ciphersuite:     s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("1703030017c947ffa470304370338bb07ce468e6b8a0944a338ba402"),
				testutil.Dehex("170303001a0cedeb922170c110c172262542c67916b78fa0d1c1261709cd00"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:            "CHACHA20-POLY1305-SHA256 with padding",
			ciphersuite:     s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("1703030021c947ffa4703043f063e7b6a0519fbd0956cf3a7c9730c13597eec17ec7e700f140"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:            "CHACHA20-POLY1305-SHA256 empty",
			ciphersuite:     s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("1703030011ef8f7a428ddc84ee5968cd6306bf1d2d1b"),
			},
			outPlaintexts: [][]byte{
				[]byte(""),
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			c, err := NewConn(&ConnOptions{
				NetConn:          &fakeConn{in: tc.completedRecords},
				Ciphersuite:      tc.ciphersuite,
				TLSVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  tc.inTrafficSecret,
				OutTrafficSecret: tc.inTrafficSecret,
			})
			if err != nil {
				t.Fatalf("NewConn() failed: %v", err)
			}
			for _, outPlaintext := range tc.outPlaintexts {
				plaintext := make([]byte, tlsRecordMaxPlaintextSize)
				n, err := c.Read(plaintext)
				if got, want := err == nil, !tc.outErr; got != want {
					t.Errorf("c.Read(plaintext) = (err=nil) = %v, want %v", got, want)
				}
				if err != nil {
					return
				}
				plaintext = plaintext[:n]
				if got, want := plaintext, outPlaintext; !bytes.Equal(got, want) {
					t.Errorf("c.Read(plaintext) = %v, want %v", got, want)
				}
			}
		})
	}
}

func TestConnReadAlert(t *testing.T) {
	// TODO(rnkim): test alerts.
}

func TestConnReadHandshake(t *testing.T) {
	// TODO(rnkim): test key updates.
}

func TestConnWrite(t *testing.T) {
	conn := &conn{}
	if _, err := conn.Write(nil); err == nil {
		t.Errorf("write is unimplemented")
	}
}
