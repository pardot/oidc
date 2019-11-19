// Code generated by protoc-gen-go. DO NOT EDIT.
// source: storage.proto

package corestate

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	any "github.com/golang/protobuf/ptypes/any"
	_ "github.com/golang/protobuf/ptypes/timestamp"
	_ "github.com/golang/protobuf/ptypes/wrappers"
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

type AuthRequest_ResponseType int32

const (
	AuthRequest_UNKNOWN AuthRequest_ResponseType = 0
	AuthRequest_CODE    AuthRequest_ResponseType = 1
	AuthRequest_TOKEN   AuthRequest_ResponseType = 2
)

var AuthRequest_ResponseType_name = map[int32]string{
	0: "UNKNOWN",
	1: "CODE",
	2: "TOKEN",
}

var AuthRequest_ResponseType_value = map[string]int32{
	"UNKNOWN": 0,
	"CODE":    1,
	"TOKEN":   2,
}

func (x AuthRequest_ResponseType) String() string {
	return proto.EnumName(AuthRequest_ResponseType_name, int32(x))
}

func (AuthRequest_ResponseType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_0d2c4ccf1453ffdb, []int{0, 0}
}

// AuthRequest represents that state for an inbound request to auth. It tracks
// this until the Code is issued, at which time it is replaced.
//
// It is keyed by a unique identifier for this flow
type AuthRequest struct {
	ClientId             string                   `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	RedirectUri          string                   `protobuf:"bytes,2,opt,name=redirect_uri,json=redirectUri,proto3" json:"redirect_uri,omitempty"`
	State                string                   `protobuf:"bytes,3,opt,name=state,proto3" json:"state,omitempty"`
	Scopes               []string                 `protobuf:"bytes,4,rep,name=scopes,proto3" json:"scopes,omitempty"`
	Nonce                string                   `protobuf:"bytes,5,opt,name=nonce,proto3" json:"nonce,omitempty"`
	ResponseType         AuthRequest_ResponseType `protobuf:"varint,6,opt,name=response_type,json=responseType,proto3,enum=deci.corestate.v1beta1.AuthRequest_ResponseType" json:"response_type,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                 `json:"-"`
	XXX_unrecognized     []byte                   `json:"-"`
	XXX_sizecache        int32                    `json:"-"`
}

func (m *AuthRequest) Reset()         { *m = AuthRequest{} }
func (m *AuthRequest) String() string { return proto.CompactTextString(m) }
func (*AuthRequest) ProtoMessage()    {}
func (*AuthRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_0d2c4ccf1453ffdb, []int{0}
}

func (m *AuthRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AuthRequest.Unmarshal(m, b)
}
func (m *AuthRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AuthRequest.Marshal(b, m, deterministic)
}
func (m *AuthRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AuthRequest.Merge(m, src)
}
func (m *AuthRequest) XXX_Size() int {
	return xxx_messageInfo_AuthRequest.Size(m)
}
func (m *AuthRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_AuthRequest.DiscardUnknown(m)
}

var xxx_messageInfo_AuthRequest proto.InternalMessageInfo

func (m *AuthRequest) GetClientId() string {
	if m != nil {
		return m.ClientId
	}
	return ""
}

func (m *AuthRequest) GetRedirectUri() string {
	if m != nil {
		return m.RedirectUri
	}
	return ""
}

func (m *AuthRequest) GetState() string {
	if m != nil {
		return m.State
	}
	return ""
}

func (m *AuthRequest) GetScopes() []string {
	if m != nil {
		return m.Scopes
	}
	return nil
}

func (m *AuthRequest) GetNonce() string {
	if m != nil {
		return m.Nonce
	}
	return ""
}

func (m *AuthRequest) GetResponseType() AuthRequest_ResponseType {
	if m != nil {
		return m.ResponseType
	}
	return AuthRequest_UNKNOWN
}

// AuthCode represents the state for a request we are going to proceed with, and
// have issued a authorization code for.
//
// It is keyed by the the ID of the auth code
type AuthCode struct {
	Code *Token `protobuf:"bytes,1,opt,name=code,proto3" json:"code,omitempty"`
	// The original request this code was written for
	AuthRequest *AuthRequest `protobuf:"bytes,2,opt,name=auth_request,json=authRequest,proto3" json:"auth_request,omitempty"`
	// metadata is implementation-specific state for this "user". it is threaded
	// through all of the steps in the process. This should contain the
	// information required to serve requests to this service.
	Metadata *any.Any `protobuf:"bytes,5,opt,name=metadata,proto3" json:"metadata,omitempty"`
	// The auth token this code was redeemed for. If a request comes in to redeem
	// a code that already has a token attached to it, we should ignore the
	// request and discard the auth token we already issued.
	//
	// https://tools.ietf.org/html/rfc6819#section-4.4.1.1
	// https://tools.ietf.org/html/rfc6819#section-5.2.1.1
	AccessToken          *Token   `protobuf:"bytes,6,opt,name=access_token,json=accessToken,proto3" json:"access_token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AuthCode) Reset()         { *m = AuthCode{} }
func (m *AuthCode) String() string { return proto.CompactTextString(m) }
func (*AuthCode) ProtoMessage()    {}
func (*AuthCode) Descriptor() ([]byte, []int) {
	return fileDescriptor_0d2c4ccf1453ffdb, []int{1}
}

func (m *AuthCode) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AuthCode.Unmarshal(m, b)
}
func (m *AuthCode) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AuthCode.Marshal(b, m, deterministic)
}
func (m *AuthCode) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AuthCode.Merge(m, src)
}
func (m *AuthCode) XXX_Size() int {
	return xxx_messageInfo_AuthCode.Size(m)
}
func (m *AuthCode) XXX_DiscardUnknown() {
	xxx_messageInfo_AuthCode.DiscardUnknown(m)
}

var xxx_messageInfo_AuthCode proto.InternalMessageInfo

func (m *AuthCode) GetCode() *Token {
	if m != nil {
		return m.Code
	}
	return nil
}

func (m *AuthCode) GetAuthRequest() *AuthRequest {
	if m != nil {
		return m.AuthRequest
	}
	return nil
}

func (m *AuthCode) GetMetadata() *any.Any {
	if m != nil {
		return m.Metadata
	}
	return nil
}

func (m *AuthCode) GetAccessToken() *Token {
	if m != nil {
		return m.AccessToken
	}
	return nil
}

// AccessToken represents an access token that was issued to the user. This is
// used for calls to the userinfo endpoint
//
// It is keyed by the the ID of the access token
type AccessToken struct {
	AccessToken          *Token   `protobuf:"bytes,1,opt,name=access_token,json=accessToken,proto3" json:"access_token,omitempty"`
	Metadata             *any.Any `protobuf:"bytes,2,opt,name=metadata,proto3" json:"metadata,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AccessToken) Reset()         { *m = AccessToken{} }
func (m *AccessToken) String() string { return proto.CompactTextString(m) }
func (*AccessToken) ProtoMessage()    {}
func (*AccessToken) Descriptor() ([]byte, []int) {
	return fileDescriptor_0d2c4ccf1453ffdb, []int{2}
}

func (m *AccessToken) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AccessToken.Unmarshal(m, b)
}
func (m *AccessToken) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AccessToken.Marshal(b, m, deterministic)
}
func (m *AccessToken) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AccessToken.Merge(m, src)
}
func (m *AccessToken) XXX_Size() int {
	return xxx_messageInfo_AccessToken.Size(m)
}
func (m *AccessToken) XXX_DiscardUnknown() {
	xxx_messageInfo_AccessToken.DiscardUnknown(m)
}

var xxx_messageInfo_AccessToken proto.InternalMessageInfo

func (m *AccessToken) GetAccessToken() *Token {
	if m != nil {
		return m.AccessToken
	}
	return nil
}

func (m *AccessToken) GetMetadata() *any.Any {
	if m != nil {
		return m.Metadata
	}
	return nil
}

// RefreshToken is a RefreshToken that was issued to the user.
//
// It is keyed by the the ID of the refresh token
type RefreshToken struct {
	RefreshToken         *Token   `protobuf:"bytes,1,opt,name=refresh_token,json=refreshToken,proto3" json:"refresh_token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RefreshToken) Reset()         { *m = RefreshToken{} }
func (m *RefreshToken) String() string { return proto.CompactTextString(m) }
func (*RefreshToken) ProtoMessage()    {}
func (*RefreshToken) Descriptor() ([]byte, []int) {
	return fileDescriptor_0d2c4ccf1453ffdb, []int{3}
}

func (m *RefreshToken) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RefreshToken.Unmarshal(m, b)
}
func (m *RefreshToken) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RefreshToken.Marshal(b, m, deterministic)
}
func (m *RefreshToken) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RefreshToken.Merge(m, src)
}
func (m *RefreshToken) XXX_Size() int {
	return xxx_messageInfo_RefreshToken.Size(m)
}
func (m *RefreshToken) XXX_DiscardUnknown() {
	xxx_messageInfo_RefreshToken.DiscardUnknown(m)
}

var xxx_messageInfo_RefreshToken proto.InternalMessageInfo

func (m *RefreshToken) GetRefreshToken() *Token {
	if m != nil {
		return m.RefreshToken
	}
	return nil
}

// Token represents a single "token" that was issued to a user. this is an
// opaque value that could be used as the code, access or refresh token values.
type Token struct {
	// unique identity for this token.
	Id []byte `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// bcrypted version of the token
	Bcrypt               []byte   `protobuf:"bytes,2,opt,name=bcrypt,proto3" json:"bcrypt,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Token) Reset()         { *m = Token{} }
func (m *Token) String() string { return proto.CompactTextString(m) }
func (*Token) ProtoMessage()    {}
func (*Token) Descriptor() ([]byte, []int) {
	return fileDescriptor_0d2c4ccf1453ffdb, []int{4}
}

func (m *Token) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Token.Unmarshal(m, b)
}
func (m *Token) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Token.Marshal(b, m, deterministic)
}
func (m *Token) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Token.Merge(m, src)
}
func (m *Token) XXX_Size() int {
	return xxx_messageInfo_Token.Size(m)
}
func (m *Token) XXX_DiscardUnknown() {
	xxx_messageInfo_Token.DiscardUnknown(m)
}

var xxx_messageInfo_Token proto.InternalMessageInfo

func (m *Token) GetId() []byte {
	if m != nil {
		return m.Id
	}
	return nil
}

func (m *Token) GetBcrypt() []byte {
	if m != nil {
		return m.Bcrypt
	}
	return nil
}

func init() {
	proto.RegisterEnum("deci.corestate.v1beta1.AuthRequest_ResponseType", AuthRequest_ResponseType_name, AuthRequest_ResponseType_value)
	proto.RegisterType((*AuthRequest)(nil), "deci.corestate.v1beta1.AuthRequest")
	proto.RegisterType((*AuthCode)(nil), "deci.corestate.v1beta1.AuthCode")
	proto.RegisterType((*AccessToken)(nil), "deci.corestate.v1beta1.AccessToken")
	proto.RegisterType((*RefreshToken)(nil), "deci.corestate.v1beta1.RefreshToken")
	proto.RegisterType((*Token)(nil), "deci.corestate.v1beta1.Token")
}

func init() { proto.RegisterFile("storage.proto", fileDescriptor_0d2c4ccf1453ffdb) }

var fileDescriptor_0d2c4ccf1453ffdb = []byte{
	// 463 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x52, 0x5d, 0x6f, 0xd3, 0x30,
	0x14, 0x25, 0x59, 0x5b, 0xda, 0xeb, 0x6c, 0xaa, 0xac, 0x69, 0x0a, 0x43, 0x40, 0x09, 0x2f, 0x7d,
	0x4a, 0x3f, 0xf8, 0x03, 0x74, 0x63, 0x48, 0x68, 0x52, 0x2b, 0x59, 0xad, 0x90, 0x78, 0xa9, 0x5c,
	0xe7, 0xae, 0x8d, 0x58, 0xe3, 0x60, 0x3b, 0xa0, 0x3c, 0xf2, 0x37, 0xf8, 0xa7, 0xbc, 0xa1, 0xd8,
	0xd9, 0x08, 0x03, 0xc4, 0xf6, 0x78, 0x7c, 0x8e, 0x8f, 0xce, 0xbd, 0xe7, 0xc2, 0xa1, 0x36, 0x52,
	0xf1, 0x2d, 0xc6, 0xb9, 0x92, 0x46, 0xd2, 0x93, 0x04, 0x45, 0x1a, 0x0b, 0xa9, 0x50, 0x1b, 0x6e,
	0x30, 0xfe, 0x32, 0xd9, 0xa0, 0xe1, 0x93, 0xd3, 0x17, 0x5b, 0x29, 0xb7, 0xd7, 0x38, 0xb2, 0xaa,
	0x4d, 0x71, 0x35, 0x32, 0xe9, 0xbe, 0x92, 0xec, 0x73, 0xf7, 0xf1, 0xf4, 0xf9, 0x5d, 0xc1, 0x57,
	0xc5, 0xf3, 0x1c, 0x95, 0xae, 0xf9, 0x27, 0x77, 0x79, 0x9e, 0x95, 0x8e, 0x8a, 0xbe, 0xfb, 0x40,
	0x66, 0x85, 0xd9, 0x31, 0xfc, 0x5c, 0xa0, 0x36, 0xf4, 0x29, 0xf4, 0xc4, 0x75, 0x8a, 0x99, 0x59,
	0xa7, 0x49, 0xe8, 0x0d, 0xbc, 0x61, 0x8f, 0x75, 0xdd, 0xc3, 0xfb, 0x84, 0xbe, 0x84, 0x40, 0x61,
	0x92, 0x2a, 0x14, 0x66, 0x5d, 0xa8, 0x34, 0xf4, 0x2d, 0x4f, 0x6e, 0xde, 0x56, 0x2a, 0xa5, 0xc7,
	0xd0, 0xb6, 0xe1, 0xc3, 0x03, 0xcb, 0x39, 0x40, 0x4f, 0xa0, 0xa3, 0x85, 0xcc, 0x51, 0x87, 0xad,
	0xc1, 0xc1, 0xb0, 0xc7, 0x6a, 0x54, 0xa9, 0x33, 0x99, 0x09, 0x0c, 0xdb, 0x4e, 0x6d, 0x01, 0x5d,
	0xc1, 0xa1, 0x42, 0x9d, 0xcb, 0x4c, 0xe3, 0xda, 0x94, 0x39, 0x86, 0x9d, 0x81, 0x37, 0x3c, 0x9a,
	0x8e, 0xe3, 0xbf, 0xef, 0x27, 0x6e, 0xe4, 0x8f, 0x59, 0xfd, 0x71, 0x59, 0xe6, 0xc8, 0x02, 0xd5,
	0x40, 0xd1, 0x18, 0x82, 0x26, 0x4b, 0x09, 0x3c, 0x5e, 0xcd, 0x2f, 0xe7, 0x8b, 0x0f, 0xf3, 0xfe,
	0x23, 0xda, 0x85, 0xd6, 0xf9, 0xe2, 0xed, 0x45, 0xdf, 0xa3, 0x3d, 0x68, 0x2f, 0x17, 0x97, 0x17,
	0xf3, 0xbe, 0x1f, 0xfd, 0xf0, 0xa0, 0x5b, 0x99, 0x9f, 0xcb, 0x04, 0xe9, 0x04, 0x5a, 0x42, 0x26,
	0x68, 0x97, 0x42, 0xa6, 0xcf, 0xfe, 0x15, 0x66, 0x29, 0x3f, 0x61, 0xc6, 0xac, 0x94, 0xbe, 0x83,
	0x80, 0x17, 0x66, 0xb7, 0x56, 0x2e, 0x9c, 0xdd, 0x17, 0x99, 0xbe, 0xba, 0xc7, 0x1c, 0x8c, 0xf0,
	0x46, 0x29, 0x63, 0xe8, 0xee, 0xd1, 0xf0, 0x84, 0x1b, 0x6e, 0x37, 0x45, 0xa6, 0xc7, 0xb1, 0xab,
	0x34, 0xbe, 0xa9, 0x34, 0x9e, 0x65, 0x25, 0xbb, 0x55, 0xd1, 0x37, 0x10, 0x70, 0x21, 0x50, 0xeb,
	0xb5, 0xa9, 0xf2, 0xd8, 0x0d, 0xfe, 0x37, 0x34, 0x71, 0x5f, 0x2c, 0x88, 0xbe, 0x79, 0x40, 0x66,
	0xbf, 0xf0, 0x1f, 0x8e, 0xde, 0x43, 0x1d, 0x7f, 0x9b, 0xc2, 0xbf, 0xcf, 0x14, 0x11, 0xab, 0x1a,
	0xbb, 0x52, 0xa8, 0x77, 0xce, 0xe1, 0xac, 0x3a, 0x0c, 0x8b, 0x1f, 0x12, 0x22, 0x50, 0x0d, 0x8f,
	0x68, 0x04, 0x6d, 0x67, 0x76, 0x04, 0x7e, 0x7d, 0xe2, 0x01, 0xf3, 0xd3, 0xa4, 0xba, 0xd1, 0x8d,
	0x50, 0x65, 0xee, 0x6a, 0x0a, 0x58, 0x8d, 0xce, 0xc8, 0xc7, 0xde, 0xad, 0xf3, 0xa6, 0x63, 0x93,
	0xbe, 0xfe, 0x19, 0x00, 0x00, 0xff, 0xff, 0x22, 0x87, 0x1d, 0xae, 0xba, 0x03, 0x00, 0x00,
}
