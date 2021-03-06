// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.20.1
// source: authz.proto

package authz

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	descriptorpb "google.golang.org/protobuf/types/descriptorpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type AuthzRules struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// You can set "allow", "disallow", "any". "allow" and "disallow" can be set
	// to the role included in the roles list. "allow" is white list. "disallow"
	// is black list. If you set true to "any", all roles are allowed.
	// If multiple rules are set, the one with the highest priority will be set.
	// The priority is "allow", "disallow", "any". Also, if no rule is set, all
	// roles will be disallowed.
	//
	// allowed role list
	Allow []string `protobuf:"bytes,1,rep,name=allow,proto3" json:"allow,omitempty"`
	// disallowed role list
	Disallow []string `protobuf:"bytes,2,rep,name=disallow,proto3" json:"disallow,omitempty"`
	// if true, any role is allowed
	Any bool `protobuf:"varint,3,opt,name=any,proto3" json:"any,omitempty"`
}

func (x *AuthzRules) Reset() {
	*x = AuthzRules{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authz_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthzRules) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthzRules) ProtoMessage() {}

func (x *AuthzRules) ProtoReflect() protoreflect.Message {
	mi := &file_authz_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthzRules.ProtoReflect.Descriptor instead.
func (*AuthzRules) Descriptor() ([]byte, []int) {
	return file_authz_proto_rawDescGZIP(), []int{0}
}

func (x *AuthzRules) GetAllow() []string {
	if x != nil {
		return x.Allow
	}
	return nil
}

func (x *AuthzRules) GetDisallow() []string {
	if x != nil {
		return x.Disallow
	}
	return nil
}

func (x *AuthzRules) GetAny() bool {
	if x != nil {
		return x.Any
	}
	return false
}

var file_authz_proto_extTypes = []protoimpl.ExtensionInfo{
	{
		ExtendedType:  (*descriptorpb.ServiceOptions)(nil),
		ExtensionType: ([]string)(nil),
		Field:         51000,
		Name:          "authz.roles",
		Tag:           "bytes,51000,rep,name=roles",
		Filename:      "authz.proto",
	},
	{
		ExtendedType:  (*descriptorpb.MethodOptions)(nil),
		ExtensionType: (*AuthzRules)(nil),
		Field:         51001,
		Name:          "authz.rules",
		Tag:           "bytes,51001,opt,name=rules",
		Filename:      "authz.proto",
	},
}

// Extension fields to descriptorpb.ServiceOptions.
var (
	// authz roles list
	//
	// repeated string roles = 51000;
	E_Roles = &file_authz_proto_extTypes[0]
)

// Extension fields to descriptorpb.MethodOptions.
var (
	// authz rules
	//
	// optional authz.AuthzRules rules = 51001;
	E_Rules = &file_authz_proto_extTypes[1]
)

var File_authz_proto protoreflect.FileDescriptor

var file_authz_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x61,
	0x75, 0x74, 0x68, 0x7a, 0x1a, 0x20, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f, 0x72,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x50, 0x0a, 0x0a, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x52,
	0x75, 0x6c, 0x65, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x05, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x12, 0x1a, 0x0a, 0x08, 0x64, 0x69,
	0x73, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x08, 0x64, 0x69,
	0x73, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x12, 0x10, 0x0a, 0x03, 0x61, 0x6e, 0x79, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x03, 0x61, 0x6e, 0x79, 0x3a, 0x37, 0x0a, 0x05, 0x72, 0x6f, 0x6c, 0x65,
	0x73, 0x12, 0x1f, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4f, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x18, 0xb8, 0x8e, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x05, 0x72, 0x6f, 0x6c, 0x65,
	0x73, 0x3a, 0x49, 0x0a, 0x05, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x12, 0x1e, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x4d, 0x65, 0x74,
	0x68, 0x6f, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xb9, 0x8e, 0x03, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x11, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x7a,
	0x52, 0x75, 0x6c, 0x65, 0x73, 0x52, 0x05, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x42, 0x29, 0x5a, 0x27,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x75, 0x6c, 0x62, 0x71, 0x62,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68,
	0x7a, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_authz_proto_rawDescOnce sync.Once
	file_authz_proto_rawDescData = file_authz_proto_rawDesc
)

func file_authz_proto_rawDescGZIP() []byte {
	file_authz_proto_rawDescOnce.Do(func() {
		file_authz_proto_rawDescData = protoimpl.X.CompressGZIP(file_authz_proto_rawDescData)
	})
	return file_authz_proto_rawDescData
}

var file_authz_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_authz_proto_goTypes = []interface{}{
	(*AuthzRules)(nil),                  // 0: authz.AuthzRules
	(*descriptorpb.ServiceOptions)(nil), // 1: google.protobuf.ServiceOptions
	(*descriptorpb.MethodOptions)(nil),  // 2: google.protobuf.MethodOptions
}
var file_authz_proto_depIdxs = []int32{
	1, // 0: authz.roles:extendee -> google.protobuf.ServiceOptions
	2, // 1: authz.rules:extendee -> google.protobuf.MethodOptions
	0, // 2: authz.rules:type_name -> authz.AuthzRules
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	2, // [2:3] is the sub-list for extension type_name
	0, // [0:2] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_authz_proto_init() }
func file_authz_proto_init() {
	if File_authz_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_authz_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthzRules); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_authz_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 2,
			NumServices:   0,
		},
		GoTypes:           file_authz_proto_goTypes,
		DependencyIndexes: file_authz_proto_depIdxs,
		MessageInfos:      file_authz_proto_msgTypes,
		ExtensionInfos:    file_authz_proto_extTypes,
	}.Build()
	File_authz_proto = out.File
	file_authz_proto_rawDesc = nil
	file_authz_proto_goTypes = nil
	file_authz_proto_depIdxs = nil
}
