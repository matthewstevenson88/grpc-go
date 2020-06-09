// Code generated by protoc-gen-go. DO NOT EDIT.
// source: s2a.proto

package s2a_proto

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type ClientSessionStartReq struct {
	// The application protocols supported by the client, e.g., "grpc".
	ApplicationProtocols []string `protobuf:"bytes,1,rep,name=application_protocols,json=applicationProtocols,proto3" json:"application_protocols,omitempty"`
	// (Optional) The minimum TLS version number that the S2A's handshaker module
	// will use to set up the session. If this field is not provided, S2A will use
	// the minimum version it supports.
	MinTlsVersion TLSVersion `protobuf:"varint,2,opt,name=min_tls_version,json=minTlsVersion,proto3,enum=s2a.proto.TLSVersion" json:"min_tls_version,omitempty"`
	// (Optional) The maximum TLS version number that the S2A's handshaker module
	// will use to set up the session. If this field is not provided, S2A will use
	// the maximum version it supports.
	MaxTlsVersion TLSVersion `protobuf:"varint,3,opt,name=max_tls_version,json=maxTlsVersion,proto3,enum=s2a.proto.TLSVersion" json:"max_tls_version,omitempty"`
	// The TLS ciphersuites that the client is willing to support.
	TlsCiphersuites []Ciphersuite `protobuf:"varint,4,rep,packed,name=tls_ciphersuites,json=tlsCiphersuites,proto3,enum=s2a.proto.Ciphersuite" json:"tls_ciphersuites,omitempty"`
	// (Optional) Describes which server identities are acceptable by the client.
	// If target identities are provided and none of them matches the peer
	// identity of the server, session setup fails.
	TargetIdentities []*Identity `protobuf:"bytes,5,rep,name=target_identities,json=targetIdentities,proto3" json:"target_identities,omitempty"`
	// (Optional) Application may specify a local identity. Otherwise, S2A chooses
	// a default local identity. If a default identity cannot be determined,
	// session setup fails.
	LocalIdentity *Identity `protobuf:"bytes,6,opt,name=local_identity,json=localIdentity,proto3" json:"local_identity,omitempty"`
	// (Optional) If target name is provided, server authorization check might be
	// performed by S2A if it is configured to do so. This check is intended to
	// verify that the peer authenticated identity is authorized to run a service
	// with the target name. If this field is populated it will be used in the SNI
	// extension.
	TargetName           string   `protobuf:"bytes,7,opt,name=target_name,json=targetName,proto3" json:"target_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ClientSessionStartReq) Reset()         { *m = ClientSessionStartReq{} }
func (m *ClientSessionStartReq) String() string { return proto.CompactTextString(m) }
func (*ClientSessionStartReq) ProtoMessage()    {}
func (*ClientSessionStartReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_16c1316ad13148df, []int{0}
}

func (m *ClientSessionStartReq) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ClientSessionStartReq.Unmarshal(m, b)
}
func (m *ClientSessionStartReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ClientSessionStartReq.Marshal(b, m, deterministic)
}
func (m *ClientSessionStartReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClientSessionStartReq.Merge(m, src)
}
func (m *ClientSessionStartReq) XXX_Size() int {
	return xxx_messageInfo_ClientSessionStartReq.Size(m)
}
func (m *ClientSessionStartReq) XXX_DiscardUnknown() {
	xxx_messageInfo_ClientSessionStartReq.DiscardUnknown(m)
}

var xxx_messageInfo_ClientSessionStartReq proto.InternalMessageInfo

func (m *ClientSessionStartReq) GetApplicationProtocols() []string {
	if m != nil {
		return m.ApplicationProtocols
	}
	return nil
}

func (m *ClientSessionStartReq) GetMinTlsVersion() TLSVersion {
	if m != nil {
		return m.MinTlsVersion
	}
	return TLSVersion_TLS1_2
}

func (m *ClientSessionStartReq) GetMaxTlsVersion() TLSVersion {
	if m != nil {
		return m.MaxTlsVersion
	}
	return TLSVersion_TLS1_2
}

func (m *ClientSessionStartReq) GetTlsCiphersuites() []Ciphersuite {
	if m != nil {
		return m.TlsCiphersuites
	}
	return nil
}

func (m *ClientSessionStartReq) GetTargetIdentities() []*Identity {
	if m != nil {
		return m.TargetIdentities
	}
	return nil
}

func (m *ClientSessionStartReq) GetLocalIdentity() *Identity {
	if m != nil {
		return m.LocalIdentity
	}
	return nil
}

func (m *ClientSessionStartReq) GetTargetName() string {
	if m != nil {
		return m.TargetName
	}
	return ""
}

type ServerSessionStartReq struct {
	// The application protocols supported by the server, e.g., "grpc".
	ApplicationProtocols []string `protobuf:"bytes,1,rep,name=application_protocols,json=applicationProtocols,proto3" json:"application_protocols,omitempty"`
	// (Optional) The minimum TLS version number that the S2A's handshaker module
	// will use to set up the session. If this field is not provided, S2A will use
	// the minimum version it supports.
	MinTlsVersion TLSVersion `protobuf:"varint,2,opt,name=min_tls_version,json=minTlsVersion,proto3,enum=s2a.proto.TLSVersion" json:"min_tls_version,omitempty"`
	// (Optional) The maximum TLS version number that the S2A's handshaker module
	// will use to set up the session. If this field is not provided, S2A will use
	// the maximum version it supports.
	MaxTlsVersion TLSVersion `protobuf:"varint,3,opt,name=max_tls_version,json=maxTlsVersion,proto3,enum=s2a.proto.TLSVersion" json:"max_tls_version,omitempty"`
	// The TLS ciphersuites that the server is willing to support.
	TlsCiphersuites []Ciphersuite `protobuf:"varint,4,rep,packed,name=tls_ciphersuites,json=tlsCiphersuites,proto3,enum=s2a.proto.Ciphersuite" json:"tls_ciphersuites,omitempty"`
	// (Optional) A list of local identities supported by the server, if
	// specified. Otherwise, S2A chooses a default local identity.
	LocalIdentities []*Identity `protobuf:"bytes,5,rep,name=local_identities,json=localIdentities,proto3" json:"local_identities,omitempty"`
	// The byte representation of the first handshake message received from the
	// client peer. It is possible that this first message is split into multiple
	// chunks. In this case, the first chunk is sent using this field and the
	// following chunks are sent using the in_bytes field of SessionNextReq
	// Specifically, if the client peer is using S2A, this field contains the
	// bytes in the out_frames field of SessionResp message that the client peer
	// received from its S2A after initiating the handshake.
	InBytes              []byte   `protobuf:"bytes,6,opt,name=in_bytes,json=inBytes,proto3" json:"in_bytes,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ServerSessionStartReq) Reset()         { *m = ServerSessionStartReq{} }
func (m *ServerSessionStartReq) String() string { return proto.CompactTextString(m) }
func (*ServerSessionStartReq) ProtoMessage()    {}
func (*ServerSessionStartReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_16c1316ad13148df, []int{1}
}

func (m *ServerSessionStartReq) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ServerSessionStartReq.Unmarshal(m, b)
}
func (m *ServerSessionStartReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ServerSessionStartReq.Marshal(b, m, deterministic)
}
func (m *ServerSessionStartReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ServerSessionStartReq.Merge(m, src)
}
func (m *ServerSessionStartReq) XXX_Size() int {
	return xxx_messageInfo_ServerSessionStartReq.Size(m)
}
func (m *ServerSessionStartReq) XXX_DiscardUnknown() {
	xxx_messageInfo_ServerSessionStartReq.DiscardUnknown(m)
}

var xxx_messageInfo_ServerSessionStartReq proto.InternalMessageInfo

func (m *ServerSessionStartReq) GetApplicationProtocols() []string {
	if m != nil {
		return m.ApplicationProtocols
	}
	return nil
}

func (m *ServerSessionStartReq) GetMinTlsVersion() TLSVersion {
	if m != nil {
		return m.MinTlsVersion
	}
	return TLSVersion_TLS1_2
}

func (m *ServerSessionStartReq) GetMaxTlsVersion() TLSVersion {
	if m != nil {
		return m.MaxTlsVersion
	}
	return TLSVersion_TLS1_2
}

func (m *ServerSessionStartReq) GetTlsCiphersuites() []Ciphersuite {
	if m != nil {
		return m.TlsCiphersuites
	}
	return nil
}

func (m *ServerSessionStartReq) GetLocalIdentities() []*Identity {
	if m != nil {
		return m.LocalIdentities
	}
	return nil
}

func (m *ServerSessionStartReq) GetInBytes() []byte {
	if m != nil {
		return m.InBytes
	}
	return nil
}

type SessionNextReq struct {
	// The byte representation of session setup, i.e., handshake messages.
	// Specifically:
	//  - All handshake messages sent from the server to the client.
	//  - All, except for the first, handshake messages sent from the client to
	//    the server. Note that the first message is communicated to S2A using the
	//    in_bytes field of ServerSessionStartReq.
	// If the peer is using S2A, this field contains the bytes in the out_frames
	// field of SessionResp message that the peer received from its S2A.
	InBytes              []byte   `protobuf:"bytes,1,opt,name=in_bytes,json=inBytes,proto3" json:"in_bytes,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SessionNextReq) Reset()         { *m = SessionNextReq{} }
func (m *SessionNextReq) String() string { return proto.CompactTextString(m) }
func (*SessionNextReq) ProtoMessage()    {}
func (*SessionNextReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_16c1316ad13148df, []int{2}
}

func (m *SessionNextReq) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SessionNextReq.Unmarshal(m, b)
}
func (m *SessionNextReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SessionNextReq.Marshal(b, m, deterministic)
}
func (m *SessionNextReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SessionNextReq.Merge(m, src)
}
func (m *SessionNextReq) XXX_Size() int {
	return xxx_messageInfo_SessionNextReq.Size(m)
}
func (m *SessionNextReq) XXX_DiscardUnknown() {
	xxx_messageInfo_SessionNextReq.DiscardUnknown(m)
}

var xxx_messageInfo_SessionNextReq proto.InternalMessageInfo

func (m *SessionNextReq) GetInBytes() []byte {
	if m != nil {
		return m.InBytes
	}
	return nil
}

type ResumptionTicketReq struct {
	// The byte representation of a NewSessionTicket message received from the
	// server.
	InBytes              []byte   `protobuf:"bytes,1,opt,name=in_bytes,json=inBytes,proto3" json:"in_bytes,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ResumptionTicketReq) Reset()         { *m = ResumptionTicketReq{} }
func (m *ResumptionTicketReq) String() string { return proto.CompactTextString(m) }
func (*ResumptionTicketReq) ProtoMessage()    {}
func (*ResumptionTicketReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_16c1316ad13148df, []int{3}
}

func (m *ResumptionTicketReq) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ResumptionTicketReq.Unmarshal(m, b)
}
func (m *ResumptionTicketReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ResumptionTicketReq.Marshal(b, m, deterministic)
}
func (m *ResumptionTicketReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ResumptionTicketReq.Merge(m, src)
}
func (m *ResumptionTicketReq) XXX_Size() int {
	return xxx_messageInfo_ResumptionTicketReq.Size(m)
}
func (m *ResumptionTicketReq) XXX_DiscardUnknown() {
	xxx_messageInfo_ResumptionTicketReq.DiscardUnknown(m)
}

var xxx_messageInfo_ResumptionTicketReq proto.InternalMessageInfo

func (m *ResumptionTicketReq) GetInBytes() []byte {
	if m != nil {
		return m.InBytes
	}
	return nil
}

type SessionReq struct {
	// Types that are valid to be assigned to ReqOneof:
	//	*SessionReq_ClientStart
	//	*SessionReq_ServerStart
	//	*SessionReq_Next
	//	*SessionReq_ResumptionTicket
	ReqOneof             isSessionReq_ReqOneof `protobuf_oneof:"req_oneof"`
	XXX_NoUnkeyedLiteral struct{}              `json:"-"`
	XXX_unrecognized     []byte                `json:"-"`
	XXX_sizecache        int32                 `json:"-"`
}

func (m *SessionReq) Reset()         { *m = SessionReq{} }
func (m *SessionReq) String() string { return proto.CompactTextString(m) }
func (*SessionReq) ProtoMessage()    {}
func (*SessionReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_16c1316ad13148df, []int{4}
}

func (m *SessionReq) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SessionReq.Unmarshal(m, b)
}
func (m *SessionReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SessionReq.Marshal(b, m, deterministic)
}
func (m *SessionReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SessionReq.Merge(m, src)
}
func (m *SessionReq) XXX_Size() int {
	return xxx_messageInfo_SessionReq.Size(m)
}
func (m *SessionReq) XXX_DiscardUnknown() {
	xxx_messageInfo_SessionReq.DiscardUnknown(m)
}

var xxx_messageInfo_SessionReq proto.InternalMessageInfo

type isSessionReq_ReqOneof interface {
	isSessionReq_ReqOneof()
}

type SessionReq_ClientStart struct {
	ClientStart *ClientSessionStartReq `protobuf:"bytes,1,opt,name=client_start,json=clientStart,proto3,oneof"`
}

type SessionReq_ServerStart struct {
	ServerStart *ServerSessionStartReq `protobuf:"bytes,2,opt,name=server_start,json=serverStart,proto3,oneof"`
}

type SessionReq_Next struct {
	Next *SessionNextReq `protobuf:"bytes,3,opt,name=next,proto3,oneof"`
}

type SessionReq_ResumptionTicket struct {
	ResumptionTicket *ResumptionTicketReq `protobuf:"bytes,4,opt,name=resumption_ticket,json=resumptionTicket,proto3,oneof"`
}

func (*SessionReq_ClientStart) isSessionReq_ReqOneof() {}

func (*SessionReq_ServerStart) isSessionReq_ReqOneof() {}

func (*SessionReq_Next) isSessionReq_ReqOneof() {}

func (*SessionReq_ResumptionTicket) isSessionReq_ReqOneof() {}

func (m *SessionReq) GetReqOneof() isSessionReq_ReqOneof {
	if m != nil {
		return m.ReqOneof
	}
	return nil
}

func (m *SessionReq) GetClientStart() *ClientSessionStartReq {
	if x, ok := m.GetReqOneof().(*SessionReq_ClientStart); ok {
		return x.ClientStart
	}
	return nil
}

func (m *SessionReq) GetServerStart() *ServerSessionStartReq {
	if x, ok := m.GetReqOneof().(*SessionReq_ServerStart); ok {
		return x.ServerStart
	}
	return nil
}

func (m *SessionReq) GetNext() *SessionNextReq {
	if x, ok := m.GetReqOneof().(*SessionReq_Next); ok {
		return x.Next
	}
	return nil
}

func (m *SessionReq) GetResumptionTicket() *ResumptionTicketReq {
	if x, ok := m.GetReqOneof().(*SessionReq_ResumptionTicket); ok {
		return x.ResumptionTicket
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*SessionReq) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*SessionReq_ClientStart)(nil),
		(*SessionReq_ServerStart)(nil),
		(*SessionReq_Next)(nil),
		(*SessionReq_ResumptionTicket)(nil),
	}
}

type SessionState struct {
	// The TLS version number that the S2A's handshaker module used to set up the
	// session.
	TlsVersion TLSVersion `protobuf:"varint,1,opt,name=tls_version,json=tlsVersion,proto3,enum=s2a.proto.TLSVersion" json:"tls_version,omitempty"`
	// The TLS ciphersuite negotiated by the S2A's handshaker module.
	TlsCiphersuite Ciphersuite `protobuf:"varint,2,opt,name=tls_ciphersuite,json=tlsCiphersuite,proto3,enum=s2a.proto.Ciphersuite" json:"tls_ciphersuite,omitempty"`
	// The sequence number of the next, incoming, TLS record.
	InSequence uint64 `protobuf:"varint,3,opt,name=in_sequence,json=inSequence,proto3" json:"in_sequence,omitempty"`
	// The sequence number of the next, outgoing, TLS record.
	OutSequence uint64 `protobuf:"varint,4,opt,name=out_sequence,json=outSequence,proto3" json:"out_sequence,omitempty"`
	// The key for the inbound direction.
	InKey []byte `protobuf:"bytes,5,opt,name=in_key,json=inKey,proto3" json:"in_key,omitempty"`
	// The key for the outbound direction.
	OutKey []byte `protobuf:"bytes,6,opt,name=out_key,json=outKey,proto3" json:"out_key,omitempty"`
	// The constant part of the record nonce for the outbound direction.
	InFixedNonce []byte `protobuf:"bytes,7,opt,name=in_fixed_nonce,json=inFixedNonce,proto3" json:"in_fixed_nonce,omitempty"`
	// The constant part of the record nonce for the inbound direction.
	OutFixedNonce []byte `protobuf:"bytes,8,opt,name=out_fixed_nonce,json=outFixedNonce,proto3" json:"out_fixed_nonce,omitempty"`
	// The HMAC secret for incoming records.
	InMacSecret []byte `protobuf:"bytes,9,opt,name=in_mac_secret,json=inMacSecret,proto3" json:"in_mac_secret,omitempty"`
	// The HMAC secret for outgoing records.
	OutMacSecret         []byte   `protobuf:"bytes,10,opt,name=out_mac_secret,json=outMacSecret,proto3" json:"out_mac_secret,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SessionState) Reset()         { *m = SessionState{} }
func (m *SessionState) String() string { return proto.CompactTextString(m) }
func (*SessionState) ProtoMessage()    {}
func (*SessionState) Descriptor() ([]byte, []int) {
	return fileDescriptor_16c1316ad13148df, []int{5}
}

func (m *SessionState) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SessionState.Unmarshal(m, b)
}
func (m *SessionState) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SessionState.Marshal(b, m, deterministic)
}
func (m *SessionState) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SessionState.Merge(m, src)
}
func (m *SessionState) XXX_Size() int {
	return xxx_messageInfo_SessionState.Size(m)
}
func (m *SessionState) XXX_DiscardUnknown() {
	xxx_messageInfo_SessionState.DiscardUnknown(m)
}

var xxx_messageInfo_SessionState proto.InternalMessageInfo

func (m *SessionState) GetTlsVersion() TLSVersion {
	if m != nil {
		return m.TlsVersion
	}
	return TLSVersion_TLS1_2
}

func (m *SessionState) GetTlsCiphersuite() Ciphersuite {
	if m != nil {
		return m.TlsCiphersuite
	}
	return Ciphersuite_AES_128_GCM_SHA256
}

func (m *SessionState) GetInSequence() uint64 {
	if m != nil {
		return m.InSequence
	}
	return 0
}

func (m *SessionState) GetOutSequence() uint64 {
	if m != nil {
		return m.OutSequence
	}
	return 0
}

func (m *SessionState) GetInKey() []byte {
	if m != nil {
		return m.InKey
	}
	return nil
}

func (m *SessionState) GetOutKey() []byte {
	if m != nil {
		return m.OutKey
	}
	return nil
}

func (m *SessionState) GetInFixedNonce() []byte {
	if m != nil {
		return m.InFixedNonce
	}
	return nil
}

func (m *SessionState) GetOutFixedNonce() []byte {
	if m != nil {
		return m.OutFixedNonce
	}
	return nil
}

func (m *SessionState) GetInMacSecret() []byte {
	if m != nil {
		return m.InMacSecret
	}
	return nil
}

func (m *SessionState) GetOutMacSecret() []byte {
	if m != nil {
		return m.OutMacSecret
	}
	return nil
}

type SessionResult struct {
	// The application protocol negotiated for this session.
	ApplicationProtocol string `protobuf:"bytes,1,opt,name=application_protocol,json=applicationProtocol,proto3" json:"application_protocol,omitempty"`
	// The session state at the end. This state contains all cryptographic
	// material required to initialize the record protocol object.
	State *SessionState `protobuf:"bytes,2,opt,name=state,proto3" json:"state,omitempty"`
	// The authenticated identity of the peer.
	PeerIdentity *Identity `protobuf:"bytes,4,opt,name=peer_identity,json=peerIdentity,proto3" json:"peer_identity,omitempty"`
	// The local identity used during session setup. This could be:
	// - The local identity that the client specifies in ClientSessionStartReq.
	// - One of the local identities that the server specifies in
	//   ServerSessionStartReq.
	// - If neither client or server specifies local identities, the S2A picks the
	//   default one. In this case, this field will contain that identity.
	LocalIdentity *Identity `protobuf:"bytes,5,opt,name=local_identity,json=localIdentity,proto3" json:"local_identity,omitempty"`
	// The SHA256 hash of the local certificate used in the handshake.
	LocalCertFingerprint []byte `protobuf:"bytes,11,opt,name=local_cert_fingerprint,json=localCertFingerprint,proto3" json:"local_cert_fingerprint,omitempty"`
	// The SHA256 hash of the peer certificate used in the handshake.
	PeerCertFingerprint  []byte   `protobuf:"bytes,12,opt,name=peer_cert_fingerprint,json=peerCertFingerprint,proto3" json:"peer_cert_fingerprint,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SessionResult) Reset()         { *m = SessionResult{} }
func (m *SessionResult) String() string { return proto.CompactTextString(m) }
func (*SessionResult) ProtoMessage()    {}
func (*SessionResult) Descriptor() ([]byte, []int) {
	return fileDescriptor_16c1316ad13148df, []int{6}
}

func (m *SessionResult) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SessionResult.Unmarshal(m, b)
}
func (m *SessionResult) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SessionResult.Marshal(b, m, deterministic)
}
func (m *SessionResult) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SessionResult.Merge(m, src)
}
func (m *SessionResult) XXX_Size() int {
	return xxx_messageInfo_SessionResult.Size(m)
}
func (m *SessionResult) XXX_DiscardUnknown() {
	xxx_messageInfo_SessionResult.DiscardUnknown(m)
}

var xxx_messageInfo_SessionResult proto.InternalMessageInfo

func (m *SessionResult) GetApplicationProtocol() string {
	if m != nil {
		return m.ApplicationProtocol
	}
	return ""
}

func (m *SessionResult) GetState() *SessionState {
	if m != nil {
		return m.State
	}
	return nil
}

func (m *SessionResult) GetPeerIdentity() *Identity {
	if m != nil {
		return m.PeerIdentity
	}
	return nil
}

func (m *SessionResult) GetLocalIdentity() *Identity {
	if m != nil {
		return m.LocalIdentity
	}
	return nil
}

func (m *SessionResult) GetLocalCertFingerprint() []byte {
	if m != nil {
		return m.LocalCertFingerprint
	}
	return nil
}

func (m *SessionResult) GetPeerCertFingerprint() []byte {
	if m != nil {
		return m.PeerCertFingerprint
	}
	return nil
}

type SessionStatus struct {
	// The status code that is specific to the application and the implementation
	// of S2A, e.g., gRPC status code.
	Code uint32 `protobuf:"varint,1,opt,name=code,proto3" json:"code,omitempty"`
	// The status details.
	Details              string   `protobuf:"bytes,2,opt,name=details,proto3" json:"details,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SessionStatus) Reset()         { *m = SessionStatus{} }
func (m *SessionStatus) String() string { return proto.CompactTextString(m) }
func (*SessionStatus) ProtoMessage()    {}
func (*SessionStatus) Descriptor() ([]byte, []int) {
	return fileDescriptor_16c1316ad13148df, []int{7}
}

func (m *SessionStatus) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SessionStatus.Unmarshal(m, b)
}
func (m *SessionStatus) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SessionStatus.Marshal(b, m, deterministic)
}
func (m *SessionStatus) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SessionStatus.Merge(m, src)
}
func (m *SessionStatus) XXX_Size() int {
	return xxx_messageInfo_SessionStatus.Size(m)
}
func (m *SessionStatus) XXX_DiscardUnknown() {
	xxx_messageInfo_SessionStatus.DiscardUnknown(m)
}

var xxx_messageInfo_SessionStatus proto.InternalMessageInfo

func (m *SessionStatus) GetCode() uint32 {
	if m != nil {
		return m.Code
	}
	return 0
}

func (m *SessionStatus) GetDetails() string {
	if m != nil {
		return m.Details
	}
	return ""
}

type SessionResp struct {
	// The byte representation of the frames that should be sent to the peer. May
	// be empty if nothing needs to be sent to the peer or if in_bytes in the
	// SessionReq is incomplete. All bytes in a non-empty out_frames must be sent
	// to the peer even if the session setup status is not OK as these frames may
	// contain appropriate alerts.
	OutFrames []byte `protobuf:"bytes,1,opt,name=out_frames,json=outFrames,proto3" json:"out_frames,omitempty"`
	// Number of bytes in the in_bytes field that are consumed by S2A. It is
	// possible that part of in_bytes is unrelated to the session setup process.
	BytesConsumed uint32 `protobuf:"varint,2,opt,name=bytes_consumed,json=bytesConsumed,proto3" json:"bytes_consumed,omitempty"`
	// This is set if the session is successfully set up. out_frames may
	// still be set to frames that needs to be forwarded to the peer.
	Result *SessionResult `protobuf:"bytes,3,opt,name=result,proto3" json:"result,omitempty"`
	// Status of session setup at the current stage.
	Status               *SessionStatus `protobuf:"bytes,4,opt,name=status,proto3" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *SessionResp) Reset()         { *m = SessionResp{} }
func (m *SessionResp) String() string { return proto.CompactTextString(m) }
func (*SessionResp) ProtoMessage()    {}
func (*SessionResp) Descriptor() ([]byte, []int) {
	return fileDescriptor_16c1316ad13148df, []int{8}
}

func (m *SessionResp) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SessionResp.Unmarshal(m, b)
}
func (m *SessionResp) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SessionResp.Marshal(b, m, deterministic)
}
func (m *SessionResp) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SessionResp.Merge(m, src)
}
func (m *SessionResp) XXX_Size() int {
	return xxx_messageInfo_SessionResp.Size(m)
}
func (m *SessionResp) XXX_DiscardUnknown() {
	xxx_messageInfo_SessionResp.DiscardUnknown(m)
}

var xxx_messageInfo_SessionResp proto.InternalMessageInfo

func (m *SessionResp) GetOutFrames() []byte {
	if m != nil {
		return m.OutFrames
	}
	return nil
}

func (m *SessionResp) GetBytesConsumed() uint32 {
	if m != nil {
		return m.BytesConsumed
	}
	return 0
}

func (m *SessionResp) GetResult() *SessionResult {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *SessionResp) GetStatus() *SessionStatus {
	if m != nil {
		return m.Status
	}
	return nil
}

func init() {
	proto.RegisterType((*ClientSessionStartReq)(nil), "s2a.proto.ClientSessionStartReq")
	proto.RegisterType((*ServerSessionStartReq)(nil), "s2a.proto.ServerSessionStartReq")
	proto.RegisterType((*SessionNextReq)(nil), "s2a.proto.SessionNextReq")
	proto.RegisterType((*ResumptionTicketReq)(nil), "s2a.proto.ResumptionTicketReq")
	proto.RegisterType((*SessionReq)(nil), "s2a.proto.SessionReq")
	proto.RegisterType((*SessionState)(nil), "s2a.proto.SessionState")
	proto.RegisterType((*SessionResult)(nil), "s2a.proto.SessionResult")
	proto.RegisterType((*SessionStatus)(nil), "s2a.proto.SessionStatus")
	proto.RegisterType((*SessionResp)(nil), "s2a.proto.SessionResp")
}

func init() {
	proto.RegisterFile("s2a.proto", fileDescriptor_16c1316ad13148df)
}

var fileDescriptor_16c1316ad13148df = []byte{
	// 885 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xec, 0x54, 0xdd, 0x8e, 0x1b, 0x45,
	0x13, 0x5d, 0xff, 0xc7, 0x35, 0xfe, 0xd9, 0xf4, 0xae, 0x37, 0x93, 0x48, 0xdf, 0x87, 0xb1, 0x00,
	0x59, 0x42, 0x2c, 0x8b, 0x83, 0x10, 0x42, 0x0a, 0x90, 0x58, 0x44, 0x1b, 0x41, 0x56, 0xd0, 0x5e,
	0xb8, 0x1d, 0x4d, 0xc6, 0x95, 0xd0, 0xca, 0x4c, 0xf7, 0x6c, 0x77, 0x4f, 0x64, 0x3f, 0x07, 0x0f,
	0xc1, 0x0d, 0xf7, 0x3c, 0x07, 0x6f, 0xc1, 0x63, 0xa0, 0xae, 0x99, 0x1d, 0x8f, 0xd7, 0xde, 0x84,
	0x07, 0xe0, 0xce, 0x5d, 0x75, 0x4e, 0x75, 0xfb, 0x9c, 0x33, 0x05, 0x5d, 0x33, 0x0b, 0x4f, 0x53,
	0xad, 0xac, 0x62, 0x9b, 0x9f, 0x0f, 0x7a, 0x91, 0x4a, 0x12, 0x25, 0xf3, 0xd3, 0xe4, 0x8f, 0x06,
	0x8c, 0xe6, 0xb1, 0x40, 0x69, 0x17, 0x68, 0x8c, 0x50, 0x72, 0x61, 0x43, 0x6d, 0x39, 0x5e, 0xb1,
	0x87, 0x30, 0x0a, 0xd3, 0x34, 0x16, 0x51, 0x68, 0x85, 0x92, 0x01, 0xc1, 0x23, 0x15, 0x1b, 0xbf,
	0x36, 0x6e, 0x4c, 0xbb, 0xfc, 0xb8, 0xd2, 0xfc, 0xf1, 0xba, 0xc7, 0x1e, 0xc1, 0x30, 0x11, 0x32,
	0xb0, 0xb1, 0x09, 0xde, 0xa0, 0x76, 0xf3, 0xfc, 0xfa, 0xb8, 0x36, 0x1d, 0xcc, 0x46, 0xa7, 0xe5,
	0x0b, 0x4e, 0x2f, 0x7f, 0x58, 0xfc, 0x92, 0x37, 0x79, 0x3f, 0x11, 0xf2, 0x32, 0x36, 0xc5, 0x91,
	0xe8, 0xe1, 0x6a, 0x8b, 0xde, 0x78, 0x3b, 0x3d, 0x5c, 0x55, 0xe8, 0x8f, 0xe1, 0xd0, 0x51, 0x23,
	0x91, 0xfe, 0x8a, 0xda, 0x64, 0xc2, 0xa2, 0xf1, 0x9b, 0xe3, 0xc6, 0x74, 0x30, 0x3b, 0xa9, 0xf0,
	0xe7, 0x9b, 0x36, 0x1f, 0xda, 0xd8, 0x54, 0xce, 0x86, 0x7d, 0x0b, 0x77, 0x6d, 0xa8, 0x5f, 0xa1,
	0x0d, 0xc4, 0x12, 0xa5, 0x15, 0x56, 0xa0, 0xf1, 0x5b, 0xe3, 0xc6, 0xd4, 0x9b, 0x1d, 0x55, 0x66,
	0x3c, 0xcb, 0x9b, 0x6b, 0x7e, 0x98, 0xa3, 0x9f, 0x95, 0x60, 0xf6, 0x15, 0x0c, 0x62, 0x15, 0x85,
	0xf1, 0xf5, 0x80, 0xb5, 0xdf, 0x1e, 0xd7, 0x6e, 0xa3, 0xf7, 0x09, 0x7a, 0x7d, 0x64, 0xef, 0x81,
	0x57, 0xdc, 0x2e, 0xc3, 0x04, 0xfd, 0xce, 0xb8, 0x36, 0xed, 0x72, 0xc8, 0x4b, 0x17, 0x61, 0x82,
	0x93, 0xbf, 0xeb, 0x30, 0x5a, 0xa0, 0x7e, 0x83, 0xfa, 0x3f, 0xbb, 0x9c, 0x5d, 0x5f, 0xc3, 0xe1,
	0x96, 0xd8, 0xef, 0x70, 0x6b, 0x58, 0x95, 0xdb, 0x99, 0x75, 0x1f, 0xee, 0x08, 0x19, 0xbc, 0x58,
	0xbb, 0xab, 0x9d, 0x4d, 0x3d, 0xde, 0x11, 0xf2, 0x89, 0x3b, 0x4e, 0x3e, 0x86, 0x41, 0xa1, 0xf1,
	0x05, 0xae, 0x48, 0xe2, 0x2a, 0xb8, 0xb6, 0x0d, 0x3e, 0x83, 0x23, 0x8e, 0x26, 0x4b, 0x52, 0xa7,
	0xef, 0xa5, 0x88, 0x5e, 0xe3, 0xbb, 0x18, 0xbf, 0xd7, 0x01, 0x8a, 0xf9, 0x0e, 0xf9, 0x1d, 0xf4,
	0x22, 0xfa, 0x0c, 0x03, 0xe3, 0x1c, 0x25, 0xb4, 0x37, 0x1b, 0x57, 0x75, 0xd8, 0xf7, 0x95, 0x9e,
	0x1f, 0x70, 0x2f, 0xe7, 0x51, 0xc5, 0x8d, 0x31, 0x14, 0x8f, 0x62, 0x4c, 0x7d, 0x67, 0xcc, 0xde,
	0xf4, 0xb8, 0x31, 0x39, 0x2f, 0x1f, 0xf3, 0x29, 0x34, 0x25, 0xae, 0x2c, 0xb9, 0xe9, 0xcd, 0xee,
	0x6f, 0xd1, 0xab, 0x92, 0x9c, 0x1f, 0x70, 0x02, 0xb2, 0xe7, 0x70, 0x57, 0x97, 0xff, 0x3f, 0xb0,
	0x24, 0x80, 0xdf, 0x24, 0xf6, 0xff, 0x2b, 0xec, 0x3d, 0x1a, 0x9d, 0x1f, 0xf0, 0x43, 0x7d, 0xa3,
	0xfc, 0xc4, 0x83, 0xae, 0xc6, 0xab, 0x40, 0x49, 0x54, 0x2f, 0x27, 0xbf, 0x35, 0xa0, 0xb7, 0x79,
	0xaf, 0x45, 0xf6, 0x05, 0x78, 0xd5, 0xc8, 0xd5, 0xde, 0x16, 0x39, 0xb0, 0x9b, 0xbc, 0x7d, 0x03,
	0xc3, 0x1b, 0x79, 0x2b, 0xd2, 0x7e, 0x5b, 0xdc, 0x06, 0xdb, 0x71, 0x73, 0x9f, 0xa7, 0x90, 0x81,
	0xc1, 0xab, 0x0c, 0x65, 0x84, 0xa4, 0x4e, 0x93, 0x83, 0x90, 0x8b, 0xa2, 0xc2, 0xde, 0x87, 0x9e,
	0xca, 0xec, 0x06, 0xd1, 0x24, 0x84, 0xa7, 0x32, 0x5b, 0x42, 0x46, 0xd0, 0x16, 0x32, 0x78, 0x8d,
	0x6b, 0xbf, 0x45, 0x81, 0x68, 0x09, 0xf9, 0x3d, 0xae, 0xd9, 0x3d, 0xe8, 0x38, 0xa6, 0xab, 0xe7,
	0x39, 0x6c, 0xab, 0xcc, 0xba, 0xc6, 0x07, 0x30, 0x10, 0x32, 0x78, 0x29, 0x56, 0xb8, 0x0c, 0xa4,
	0x72, 0x43, 0x3b, 0xd4, 0xef, 0x09, 0xf9, 0xd4, 0x15, 0x2f, 0x5c, 0x8d, 0x7d, 0x04, 0x43, 0x47,
	0xaf, 0xc2, 0xee, 0x10, 0xac, 0xaf, 0x32, 0x5b, 0xc1, 0x4d, 0xa0, 0x2f, 0x64, 0x90, 0x84, 0x51,
	0x60, 0x30, 0xd2, 0x68, 0xfd, 0x2e, 0xa1, 0x3c, 0x21, 0x9f, 0x87, 0xd1, 0x82, 0x4a, 0xee, 0x46,
	0x37, 0xab, 0x02, 0x82, 0xfc, 0x46, 0x95, 0xd9, 0x12, 0x35, 0xf9, 0xab, 0x0e, 0xfd, 0x32, 0xbf,
	0x26, 0x8b, 0x2d, 0xfb, 0x0c, 0x8e, 0xf7, 0x6d, 0x20, 0xf2, 0xa7, 0xcb, 0x8f, 0xf6, 0x2c, 0x20,
	0xf6, 0x09, 0xb4, 0x8c, 0xb3, 0xb4, 0xc8, 0xe9, 0xbd, 0xdd, 0xa0, 0x91, 0xe3, 0x3c, 0x47, 0xb1,
	0x2f, 0xa1, 0x9f, 0x22, 0xea, 0xcd, 0x66, 0x6d, 0xde, 0xbe, 0x59, 0x7b, 0x0e, 0x59, 0x2e, 0xd6,
	0xdd, 0xa5, 0xdc, 0xfa, 0xd7, 0x4b, 0xf9, 0x73, 0x38, 0xc9, 0xb9, 0x11, 0x6a, 0x27, 0xb1, 0x7c,
	0x85, 0x3a, 0xd5, 0x42, 0x5a, 0xdf, 0x23, 0x5d, 0x8e, 0xa9, 0x3b, 0x47, 0x6d, 0x9f, 0x6e, 0x7a,
	0x6c, 0x06, 0x23, 0x7a, 0xeb, 0x0e, 0xa9, 0x47, 0xa4, 0x23, 0xd7, 0xbc, 0xc1, 0x99, 0x3c, 0x2a,
	0x25, 0x75, 0x7f, 0x3b, 0x33, 0x8c, 0x41, 0x33, 0x52, 0x4b, 0x24, 0x09, 0xfb, 0x9c, 0x7e, 0x33,
	0x1f, 0x3a, 0x4b, 0xb4, 0xa1, 0x88, 0x0d, 0xa9, 0xd6, 0xe5, 0xd7, 0xc7, 0xc9, 0x9f, 0x35, 0xf0,
	0x36, 0x96, 0xa4, 0xec, 0x7f, 0x00, 0x14, 0x0a, 0x1d, 0x26, 0xe5, 0xfe, 0xe9, 0xba, 0x3c, 0x50,
	0x81, 0x7d, 0x08, 0x03, 0xda, 0x4c, 0x41, 0xa4, 0xa4, 0xc9, 0x12, 0x5c, 0xd2, 0xbc, 0x3e, 0xef,
	0x53, 0x75, 0x5e, 0x14, 0xd9, 0x19, 0xb4, 0x35, 0x19, 0x5c, 0x6c, 0x03, 0x7f, 0xd7, 0xa4, 0x3c,
	0x00, 0xbc, 0xc0, 0x39, 0x86, 0xa1, 0xf7, 0x17, 0xfe, 0xf8, 0xfb, 0x6d, 0xcd, 0x0c, 0x2f, 0x70,
	0xb3, 0x9f, 0x00, 0x16, 0xb3, 0xc7, 0x6e, 0x35, 0x89, 0x08, 0xd9, 0xdc, 0x7d, 0xef, 0xf6, 0xe7,
	0xb4, 0xc0, 0xb2, 0xd1, 0xbe, 0x1b, 0xaf, 0x1e, 0x9c, 0xec, 0x7d, 0x48, 0x3a, 0x39, 0x98, 0xd6,
	0xce, 0x6a, 0x2f, 0xda, 0xd4, 0x78, 0xf8, 0x4f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x95, 0x97, 0x8c,
	0xad, 0x05, 0x09, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// S2AServiceClient is the client API for S2AService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type S2AServiceClient interface {
	// S2A service accepts a stream of session setup requests and returns a stream
	// of session setup responses. The client of this service is expected to send
	// exactly one client_start or server_start message followed by at least one
	// next message. Applications running TLS clients can send requests with
	// resumption_ticket messages only after the session is successfully set up.
	//
	// Every time S2A client sends a request, this service sends a response.
	// However, clients do not have to wait for service response before sending
	// the next request.
	SetUpSession(ctx context.Context, opts ...grpc.CallOption) (S2AService_SetUpSessionClient, error)
}

type s2AServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewS2AServiceClient(cc grpc.ClientConnInterface) S2AServiceClient {
	return &s2AServiceClient{cc}
}

func (c *s2AServiceClient) SetUpSession(ctx context.Context, opts ...grpc.CallOption) (S2AService_SetUpSessionClient, error) {
	stream, err := c.cc.NewStream(ctx, &_S2AService_serviceDesc.Streams[0], "/s2a.proto.S2AService/SetUpSession", opts...)
	if err != nil {
		return nil, err
	}
	x := &s2AServiceSetUpSessionClient{stream}
	return x, nil
}

type S2AService_SetUpSessionClient interface {
	Send(*SessionReq) error
	Recv() (*SessionResp, error)
	grpc.ClientStream
}

type s2AServiceSetUpSessionClient struct {
	grpc.ClientStream
}

func (x *s2AServiceSetUpSessionClient) Send(m *SessionReq) error {
	return x.ClientStream.SendMsg(m)
}

func (x *s2AServiceSetUpSessionClient) Recv() (*SessionResp, error) {
	m := new(SessionResp)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// S2AServiceServer is the server API for S2AService service.
type S2AServiceServer interface {
	// S2A service accepts a stream of session setup requests and returns a stream
	// of session setup responses. The client of this service is expected to send
	// exactly one client_start or server_start message followed by at least one
	// next message. Applications running TLS clients can send requests with
	// resumption_ticket messages only after the session is successfully set up.
	//
	// Every time S2A client sends a request, this service sends a response.
	// However, clients do not have to wait for service response before sending
	// the next request.
	SetUpSession(S2AService_SetUpSessionServer) error
}

// UnimplementedS2AServiceServer can be embedded to have forward compatible implementations.
type UnimplementedS2AServiceServer struct {
}

func (*UnimplementedS2AServiceServer) SetUpSession(srv S2AService_SetUpSessionServer) error {
	return status.Errorf(codes.Unimplemented, "method SetUpSession not implemented")
}

func RegisterS2AServiceServer(s *grpc.Server, srv S2AServiceServer) {
	s.RegisterService(&_S2AService_serviceDesc, srv)
}

func _S2AService_SetUpSession_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(S2AServiceServer).SetUpSession(&s2AServiceSetUpSessionServer{stream})
}

type S2AService_SetUpSessionServer interface {
	Send(*SessionResp) error
	Recv() (*SessionReq, error)
	grpc.ServerStream
}

type s2AServiceSetUpSessionServer struct {
	grpc.ServerStream
}

func (x *s2AServiceSetUpSessionServer) Send(m *SessionResp) error {
	return x.ServerStream.SendMsg(m)
}

func (x *s2AServiceSetUpSessionServer) Recv() (*SessionReq, error) {
	m := new(SessionReq)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _S2AService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "s2a.proto.S2AService",
	HandlerType: (*S2AServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "SetUpSession",
			Handler:       _S2AService_SetUpSession_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "s2a.proto",
}