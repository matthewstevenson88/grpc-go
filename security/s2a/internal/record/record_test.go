package record

import (
	"bytes"
	"errors"
	"net"
	"reflect"
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
				HSAddr:           "test handshaker address",
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
				HSAddr:           "test handshaker address",
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
				HSAddr:           "test handshaker address",
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
				HSAddr:           "test handshaker address",
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
				HSAddr:           "test handshaker address",
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
				HSAddr:           "test handshaker address",
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
				HSAddr:           "test handshaker address",
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
				t.Errorf("conn.HSAddr = %v, want %v", got, want)
			}
		})
	}
}

func TestStripPaddingAndType(t *testing.T) {
	for _, tc := range []struct {
		desc                                              string
		pendingApplicationData, outPendingApplicationData []byte
		outContentType                                    recordType
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
			ct, err := c.stripPaddingAndType()
			if err != nil {
				t.Errorf("c.stripPaddingAndType() failed: %v", err)
			}
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
			desc:               "header payload size same as maxLen",
			b:                  testutil.Dehex("0000000003ffffff"),
			maxLen:             3,
			outCompletedRecord: testutil.Dehex("0000000003ffffff"),
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
			completedRecord, remaining, err := parseReadBuffer(tc.b, tc.maxLen)
			if got, want := err == nil, !tc.outErr; got != want {
				t.Errorf("parseReadBuffer(%v, %v) = (err=nil) = %v, want %v", tc.b, tc.maxLen, got, want)
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
				completedRecord, err := c.readFullRecord()
				if got, want := err == nil, !tc.outErr; got != want {
					t.Errorf("c.readCompletecRecord() = (err=nil) = %v, want %v", got, want)
				}
				if err != nil {
					return
				}
				if got, want := completedRecord, outCompletedRecord; !bytes.Equal(got, want) {
					t.Errorf("c.readFullRecord() = %v, want %v", got, want)
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
		{
			desc:            "AES-128-GCM-SHA256 split in first record",
			ciphersuite:     s2apb.Ciphersuite_AES_128_GCM_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("1703030017f2e4e411ac6760"),
				testutil.Dehex("e4e3f074a36574c45ee4c1906103db0d"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:            "AES-256-GCM-SHA384 split in first record",
			ciphersuite:     s2apb.Ciphersuite_AES_256_GCM_SHA384,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("170303001724efee5af1a6"),
				testutil.Dehex("2170ad5a95f899d038b965386a1a7daed9"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:            "CHACHA20-POLY1305-SHA256 split in first record",
			ciphersuite:     s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("1703030017c947ffa470"),
				testutil.Dehex("304370338bb07ce468e6b8a0944a338ba402"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:            "AES-128-GCM-SHA256 split in first record header",
			ciphersuite:     s2apb.Ciphersuite_AES_128_GCM_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("17"),
				testutil.Dehex("03030017f2e4e411ac6760e4e3f074a36574c45ee4c1906103db0d"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:            "AES-256-GCM-SHA384 split in first record header",
			ciphersuite:     s2apb.Ciphersuite_AES_256_GCM_SHA384,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("17"),
				testutil.Dehex("0303001724efee5af1a62170ad5a95f899d038b965386a1a7daed9"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:            "CHACHA20-POLY1305-SHA256 split in first record header",
			ciphersuite:     s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("17"),
				testutil.Dehex("03030017c947ffa470304370338bb07ce468e6b8a0944a338ba402"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
			},
		},
		{
			desc:            "AES-128-GCM-SHA256 split in second record",
			ciphersuite:     s2apb.Ciphersuite_AES_128_GCM_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("1703030017f2e4e411ac6760e4e3f074a36574c45ee4c1906103db0d170303001ad7"),
				testutil.Dehex("853afd6d7ceaabab950a0b6707905d2b908894871c7c62021f"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:            "AES-256-GCM-SHA384 split in second record",
			ciphersuite:     s2apb.Ciphersuite_AES_256_GCM_SHA384,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("170303001724efee5af1a62170ad5a95f899d038b965386a1a7daed9170303001a83"),
				testutil.Dehex("2a5fd271b6442e74bc02111a8e8b52a74b14dd3eca8598b293"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:            "CHACHA20-POLY1305-SHA256 split in second record",
			ciphersuite:     s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("1703030017c947ffa470304370338bb07ce468e6b8a0944a338ba402170303001a0c"),
				testutil.Dehex("edeb922170c110c172262542c67916b78fa0d1c1261709cd00"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:            "AES-128-GCM-SHA256 split in second record header",
			ciphersuite:     s2apb.Ciphersuite_AES_128_GCM_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("1703030017f2e4e411ac6760e4e3f074a36574c45ee4c1906103db0d17"),
				testutil.Dehex("0303001ad7853afd6d7ceaabab950a0b6707905d2b908894871c7c62021f"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:            "AES-256-GCM-SHA384 split in second record header",
			ciphersuite:     s2apb.Ciphersuite_AES_256_GCM_SHA384,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("170303001724efee5af1a62170ad5a95f899d038b965386a1a7daed917"),
				testutil.Dehex("0303001a832a5fd271b6442e74bc02111a8e8b52a74b14dd3eca8598b293"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:            "CHACHA20-POLY1305-SHA256 split in second record header",
			ciphersuite:     s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("1703030017c947ffa470304370338bb07ce468e6b8a0944a338ba40217"),
				testutil.Dehex("0303001a0cedeb922170c110c172262542c67916b78fa0d1c1261709cd00"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:            "AES-128-GCM-SHA256 split randomly",
			ciphersuite:     s2apb.Ciphersuite_AES_128_GCM_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("1703030017f2e4e411ac6760e4"),
				testutil.Dehex("e3f074a36574c45ee4c1906103db0d17"),
				testutil.Dehex("0303001ad7853afd6d7ceaab"),
				testutil.Dehex("ab950a0b6707905d2b908894871c7c62021f"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:            "AES-256-GCM-SHA384 split randomly",
			ciphersuite:     s2apb.Ciphersuite_AES_256_GCM_SHA384,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("170303001724efee"),
				testutil.Dehex("5af1a62170ad5a95f899d038b965386a1a7daed917"),
				testutil.Dehex("03"),
				testutil.Dehex("03001a832a5fd271b6442e74bc02111a8e8b52a74b14dd3eca8598b293"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
		{
			desc:            "CHACHA20-POLY1305-SHA256 split randomly",
			ciphersuite:     s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("17"),
				testutil.Dehex("03030017c947ffa470304370338bb07ce468e6b8a0944a338ba40217"),
				testutil.Dehex("0303001a0cedeb922170"),
				testutil.Dehex("c110c172262542c67916b78fa0d1c1261709cd00"),
			},
			outPlaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			c, err := NewConn(&ConnParameters{
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
	for _, tc := range []struct {
		desc            string
		ciphersuite     s2apb.Ciphersuite
		inTrafficSecret []byte
		completedRecord []byte
		outClosed       bool
		outErr          bool
	}{
		// The records below are TLS 1.3 records that hold the ciphertext
		// obtained by encrypting (with or without padding) the close notify
		// alert {0x01, 0x00} using the keys derived from the given traffic
		// secrets and the sequence number zero.
		{
			desc:            "AES-128-GCM-SHA256 with no padding",
			ciphersuite:     s2apb.Ciphersuite_AES_128_GCM_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecord: testutil.Dehex("1703030013c2d6c245fb80969de1dd9d14499261b67735b0"),
			outClosed:       true,
		},
		{
			desc:            "AES-128-GCM-SHA256 with padding",
			ciphersuite:     s2apb.Ciphersuite_AES_128_GCM_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecord: testutil.Dehex("170303001dc2d6c225995177e84726e4886d5ea79383e5d529cd8339fbbfcafe2418"),
			outClosed:       true,
		},
		{
			desc:            "AES-256-GCM-SHA384 with no padding",
			ciphersuite:     s2apb.Ciphersuite_AES_256_GCM_SHA384,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecord: testutil.Dehex("170303001314ddc8f3b3856660bb5ac81533c157582f8b4c"),
			outClosed:       true,
		},
		{
			desc:            "AES-256-GCM-SHA384 with padding",
			ciphersuite:     s2apb.Ciphersuite_AES_256_GCM_SHA384,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecord: testutil.Dehex("170303001d14ddc86ec49036e8a4d1f269933545f03b0fe9ffd8b02acd1e41f7139e"),
			outClosed:       true,
		},
		{
			desc:            "CHACHA20-POLY1305-SHA256 with no padding",
			ciphersuite:     s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecord: testutil.Dehex("1703030013f975d9cb2f116d85d4e3859f5288a9b013d778"),
			outClosed:       true,
		},
		{
			desc:            "CHACHA20-POLY1305-SHA256 with padding",
			ciphersuite:     s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecord: testutil.Dehex("170303001df975d990450654f063e7b6a0514c2714c9827e796071389802f451585a"),
			outClosed:       true,
		},
		// The records below are TLS 1.3 records that hold the ciphertext
		// obtained by encrypting the alert {0x01, 0x2c} using the keys derived
		// from the given traffic secrets and the sequence number zero.
		{
			desc:            "AES-128-GCM-SHA256 other alert",
			ciphersuite:     s2apb.Ciphersuite_AES_128_GCM_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecord: testutil.Dehex("1703030013c2fac23f995cbe79a8d1e4c8f0353afefeaac9"),
		},
		{
			desc:            "AES-256-GCM-SHA384 other alert",
			ciphersuite:     s2apb.Ciphersuite_AES_256_GCM_SHA384,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecord: testutil.Dehex("170303001314f1c80add85193c9598219ae9dc26f2479ccf"),
		},
		{
			desc:            "CHACHA20-POLY1305-SHA256 other alert",
			ciphersuite:     s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecord: testutil.Dehex("1703030013f959d96fed92bdc7e85e04e86c19eaf154b052"),
		},
		// The records below are TLS 1.3 records that hold the ciphertext
		// obtained by encrypting the message {0x01} using the keys derived
		// from the given traffic secrets and the sequence number zero. The
		// first byte of this message indicates that it should be an alert
		// message, but the length of the message is too small.
		{
			desc:            "AES-128-GCM-SHA256 invalid",
			ciphersuite:     s2apb.Ciphersuite_AES_128_GCM_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecord: testutil.Dehex("1703030012c2c351fc48d9ac84fa165adcc9a26ffbc3c7"),
			outErr:          true,
		},
		{
			desc:            "AES-256-GCM-SHA384 invalid",
			ciphersuite:     s2apb.Ciphersuite_AES_256_GCM_SHA384,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecord: testutil.Dehex("170303001214c8476102a460b5cf9e9ba59e1726215ca9"),
			outErr:          true,
		},
		{
			desc:            "CHACHA20-POLY1305-SHA256 invalid",
			ciphersuite:     s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecord: testutil.Dehex("1703030012f9606a83ac17b165a51f3fe764da8560c706"),
			outErr:          true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			f := &fakeConn{in: [][]byte{tc.completedRecord}}
			c, err := NewConn(&ConnParameters{
				NetConn:          f,
				Ciphersuite:      tc.ciphersuite,
				TLSVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  tc.inTrafficSecret,
				OutTrafficSecret: tc.inTrafficSecret,
			})
			if err != nil {
				t.Fatalf("NewConn() failed: %v", err)
			}
			plaintext := make([]byte, tlsRecordMaxPlaintextSize)
			_, err = c.Read(plaintext)
			if got, want := err == nil, !tc.outErr; got != want {
				t.Errorf("c.Read(plaintext) = (err=nil) = %v, want %v", got, want)
			}
			if err != nil {
				return
			}
			if got, want := f.closed, tc.outClosed; got != want {
				t.Errorf("f.closed = %v, want %v", got, want)
			}
		})
	}
}

func TestConnReadKeyUpdate(t *testing.T) {
	for _, tc := range []struct {
		desc             string
		ciphersuite      s2apb.Ciphersuite
		inTrafficSecret  []byte
		completedRecords [][]byte
		outPlaintexts    [][]byte
	}{
		{
			desc:            "AES-128-GCM-SHA256",
			ciphersuite:     s2apb.Ciphersuite_AES_128_GCM_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("1703030020dbd6d724994777e84726e4886d7432e311a73b42d0073f28ea60e30e8eb498fd"),
				testutil.Dehex("1703030017dd99ebef48292cd4c372a000740372d2ae9aad31cfd274"),
			},
			outPlaintexts: [][]byte{
				[]byte(""),
				[]byte("123456"),
			},
		},
		{
			desc:            "AES-256-GCM-SHA384",
			ciphersuite:     s2apb.Ciphersuite_AES_256_GCM_SHA384,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("17030300200ddddd6fc48636e8a4d1f269930e7835adc07e732ba7fd617ff9a65a51c36b6d"),
				testutil.Dehex("17030300179cd5972e76baf56af644c92235460301c0a013ad35be00"),
			},
			outPlaintexts: [][]byte{
				[]byte(""),
				[]byte("123456"),
			},
		},
		{
			desc:            "CHACHA20-POLY1305-SHA256",
			ciphersuite:     s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			inTrafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			completedRecords: [][]byte{
				testutil.Dehex("1703030020e075cc91451054f063e7b6a0519fbd098e83bda4b515bea5196cccc008556ad0"),
				testutil.Dehex("1703030017c4e48ccaf036bd9bc146bbc6192404f9a2d2da5d1afe78"),
			},
			outPlaintexts: [][]byte{
				[]byte(""),
				[]byte("123456"),
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			c, err := NewConn(&ConnParameters{
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
				if err != nil {
					t.Fatalf("c.Read(plaintext) failed: %v", err)
				}
				plaintext = plaintext[:n]
				if got, want := plaintext, outPlaintext; !bytes.Equal(got, want) {
					t.Errorf("c.Read(plaintext) = %v, want %v", got, want)
				}
			}
		})
	}
}

func TestBuildValidHeader(t *testing.T) {
	for _, tc := range []struct {
		desc           string
		payloadLength  int
		expectedHeader []byte
		outErr         error
	}{
		{
			desc:           "Payload with length 0",
			payloadLength:  0,
			expectedHeader: []byte{tlsApplicationData, tlsLegacyRecordVersion, tlsLegacyRecordVersion, 0, 16},
		},
		{
			desc:           "Payload with length 6",
			payloadLength:  6,
			expectedHeader: []byte{tlsApplicationData, tlsLegacyRecordVersion, tlsLegacyRecordVersion, 0, 22},
		},
		{
			desc:           "Payload with length 256",
			payloadLength:  256,
			expectedHeader: []byte{tlsApplicationData, tlsLegacyRecordVersion, tlsLegacyRecordVersion, 1, 16},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			resultHeader, err := buildHeader(tc.payloadLength, tlsRecordMaxPayloadSize)
			if !bytes.Equal(tc.expectedHeader, resultHeader) {
				t.Errorf("Incorrect Header: Expected: %v, Received: %v", tc.expectedHeader, resultHeader)
			}
			if got, want := err == nil, tc.outErr == nil; got != want {
				t.Errorf("Incorrect Error: Expected: %v, Received: %v", tc.outErr, err)
			}
		})
	}
}

func TestBuildInvalidheader(t *testing.T) {
	for _, tc := range []struct {
		desc           string
		payloadLength  int
		expectedHeader []byte
		outErr         error
	}{
		{
			desc:          "Payload with length greater than max payload size",
			payloadLength: tlsRecordMaxPayloadSize + 1,
			outErr:        errors.New("payload length exceeds max allowed size"),
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			resultHeader, err := buildHeader(tc.payloadLength, tlsRecordMaxPayloadSize)
			if !bytes.Equal(tc.expectedHeader, resultHeader) {
				t.Errorf("Incorrect Header: Expected: %v, Received: %v", tc.expectedHeader, resultHeader)
			}
			if got, want := err == nil, tc.outErr == nil; got != want {
				t.Errorf("Incorrect Error: Expected: %v, Received: %v", tc.outErr, err)
			}
		})
	}
}

func TestConnWrite(t *testing.T) {
	for _, tc := range []struct {
		desc             string
		ciphersuite      s2apb.Ciphersuite
		trafficSecret    []byte
		plaintexts       [][]byte
		maxPlaintextSize int
		outRecords       [][]byte
		outBytesWritten  []int
		outErr           bool
	}{
		// The traffic secrets were chosen randomly and are equivalent to the
		// ones used in C++ and Java. The ciphertext was constructed using an
		// existing TLS library.

		{
			desc:          "AES-128-GCM-SHA256 plaintext split in 2 records",
			ciphersuite:   s2apb.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			plaintexts: [][]byte{
				[]byte("123456"),
			},
			maxPlaintextSize: 3,
			outRecords: [][]byte{
				testutil.Dehex("1703030014f2e4e432b1c71d1071abf6d5e1f7b32a158c4872"),
				testutil.Dehex("1703030014f78835db07e7d1ceb81ad7c0698ad4aeff469bb6"),
			},
			outBytesWritten: []int{6},
		},
		{
			desc:          "AES-128-GCM-SHA256",
			ciphersuite:   s2apb.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			plaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
			maxPlaintextSize: tlsRecordMaxPlaintextSize,
			outRecords: [][]byte{
				testutil.Dehex("1703030017f2e4e411ac6760e4e3f074a36574c45ee4c1906103db0d"),
				testutil.Dehex("170303001ad7853afd6d7ceaabab950a0b6707905d2b908894871c7c62021f"),
			},
			outBytesWritten: []int{6, 9},
		},
		{
			desc:          "AES-128-GCM-SHA256 empty",
			ciphersuite:   s2apb.Ciphersuite_AES_128_GCM_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			plaintexts: [][]byte{
				[]byte(""),
			},
			maxPlaintextSize: tlsRecordMaxPlaintextSize,
			outRecords: [][]byte{
				testutil.Dehex("1703030011d47cb2ec040f26cc8989330339c669dd4e"),
			},
			outBytesWritten: []int{0},
		},
		{
			desc:          "AES-256-GCM-SHA384 plaintext split in 2 records",
			ciphersuite:   s2apb.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			plaintexts: [][]byte{
				[]byte("123456"),
			},
			maxPlaintextSize: 3,
			outRecords: [][]byte{
				testutil.Dehex("170303001424efee7905fc3ab0938bf9a03b1788460cb2b39b"),
				testutil.Dehex("1703030014a32750f43dbf6371e3ceab7200f28b68bb523d46"),
			},
			outBytesWritten: []int{6},
		},
		{
			desc:          "AES-256-GCM-SHA384",
			ciphersuite:   s2apb.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			plaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
			maxPlaintextSize: tlsRecordMaxPlaintextSize,
			outRecords: [][]byte{
				testutil.Dehex("170303001724efee5af1a62170ad5a95f899d038b965386a1a7daed9"),
				testutil.Dehex("170303001a832a5fd271b6442e74bc02111a8e8b52a74b14dd3eca8598b293"),
			},
			outBytesWritten: []int{6, 9},
		},
		{
			desc:          "AES-256-GCM-SHA384 empty",
			ciphersuite:   s2apb.Ciphersuite_AES_256_GCM_SHA384,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			plaintexts: [][]byte{
				[]byte(""),
			},
			maxPlaintextSize: tlsRecordMaxPlaintextSize,
			outRecords: [][]byte{
				testutil.Dehex("170303001102a04134d38c1118f36b01d177c5d2dcf7"),
			},
			outBytesWritten: []int{0},
		},
		{
			desc:          "CHACHA20-POLY1305-SHA256 plaintext split in 2 records",
			ciphersuite:   s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			plaintexts: [][]byte{
				[]byte("123456"),
			},
			maxPlaintextSize: 3,
			outRecords: [][]byte{
				testutil.Dehex("1703030014c947ff873efb31727561a3e3432380c89113e6eb"),
				testutil.Dehex("17030300142ce0e4b4fc51399db8c264f2aec8870830fd02d3"),
			},
			outBytesWritten: []int{6},
		},
		{
			desc:          "CHACHA20-POLY1305-SHA256",
			ciphersuite:   s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			plaintexts: [][]byte{
				[]byte("123456"),
				[]byte("789123456"),
			},
			maxPlaintextSize: tlsRecordMaxPlaintextSize,
			outRecords: [][]byte{
				testutil.Dehex("1703030017c947ffa470304370338bb07ce468e6b8a0944a338ba402"),
				testutil.Dehex("170303001a0cedeb922170c110c172262542c67916b78fa0d1c1261709cd00"),
			},
			outBytesWritten: []int{6, 9},
		},
		{
			desc:          "CHACHA20-POLY1305-SHA256 empty",
			ciphersuite:   s2apb.Ciphersuite_CHACHA20_POLY1305_SHA256,
			trafficSecret: testutil.Dehex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
			plaintexts: [][]byte{
				[]byte(""),
			},
			maxPlaintextSize: tlsRecordMaxPlaintextSize,
			outRecords: [][]byte{
				testutil.Dehex("1703030011ef8f7a428ddc84ee5968cd6306bf1d2d1b"),
			},
			outBytesWritten: []int{0},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			fConn := &fakeConn{}
			newConn, err := NewConn(&ConnParameters{
				NetConn:          fConn,
				Ciphersuite:      tc.ciphersuite,
				TLSVersion:       s2apb.TLSVersion_TLS1_3,
				InTrafficSecret:  tc.trafficSecret,
				OutTrafficSecret: tc.trafficSecret,
			})
			c := newConn.(*conn)
			if err != nil {
				t.Fatalf("NewConn() failed: %v", err)
			}
			for i, plaintext := range tc.plaintexts {
				bytesWritten, err := c.writeTLSRecord(plaintext, tlsApplicationData, tc.maxPlaintextSize)
				if got, want := err == nil, !tc.outErr; got != want {
					t.Errorf("c.Write(plaintext) = (err=nil) = %v, want %v", got, want)
				}
				if bytesWritten != tc.outBytesWritten[i] {
					t.Errorf("Incorrect number of bytes written: got: %v, want: %v", bytesWritten, tc.outBytesWritten[i])
				}
			}
			if !reflect.DeepEqual(fConn.out, tc.outRecords) {
				t.Errorf("Incorrect Record: got: %v, want: %v", fConn.out, tc.outRecords)
			}
		})
	}
}

// TODO(gud): Add roundtrip tests.
// TODO(gud): Remember to test the case where the payload size is maximum (2^14)
