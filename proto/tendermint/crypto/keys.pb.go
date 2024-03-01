// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: tendermint/crypto/keys.proto

package crypto

import (
	bytes "bytes"
	fmt "fmt"
	_ "github.com/cosmos/gogoproto/gogoproto"
	proto "github.com/cosmos/gogoproto/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// PublicKey defines the keys available for use with Validators
type PublicKey struct {
	// Types that are valid to be assigned to Sum:
	//
	//	*PublicKey_Ed25519
	//	*PublicKey_Secp256K1
	//	*PublicKey_Secp256K1Uncompressed
	Sum isPublicKey_Sum `protobuf_oneof:"sum"`
}

func (m *PublicKey) Reset()         { *m = PublicKey{} }
func (m *PublicKey) String() string { return proto.CompactTextString(m) }
func (*PublicKey) ProtoMessage()    {}
func (*PublicKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_cb048658b234868c, []int{0}
}
func (m *PublicKey) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *PublicKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_PublicKey.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *PublicKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PublicKey.Merge(m, src)
}
func (m *PublicKey) XXX_Size() int {
	return m.Size()
}
func (m *PublicKey) XXX_DiscardUnknown() {
	xxx_messageInfo_PublicKey.DiscardUnknown(m)
}

var xxx_messageInfo_PublicKey proto.InternalMessageInfo

type isPublicKey_Sum interface {
	isPublicKey_Sum()
	Equal(interface{}) bool
	MarshalTo([]byte) (int, error)
	Size() int
	Compare(interface{}) int
}

type PublicKey_Ed25519 struct {
	Ed25519 []byte `protobuf:"bytes,1,opt,name=ed25519,proto3,oneof" json:"ed25519,omitempty"`
}
type PublicKey_Secp256K1 struct {
	Secp256K1 []byte `protobuf:"bytes,2,opt,name=secp256k1,proto3,oneof" json:"secp256k1,omitempty"`
}
type PublicKey_Secp256K1Uncompressed struct {
	Secp256K1Uncompressed []byte `protobuf:"bytes,3,opt,name=secp256k1_uncompressed,json=secp256k1Uncompressed,proto3,oneof" json:"secp256k1_uncompressed,omitempty"`
}

func (*PublicKey_Ed25519) isPublicKey_Sum()               {}
func (*PublicKey_Secp256K1) isPublicKey_Sum()             {}
func (*PublicKey_Secp256K1Uncompressed) isPublicKey_Sum() {}

func (m *PublicKey) GetSum() isPublicKey_Sum {
	if m != nil {
		return m.Sum
	}
	return nil
}

func (m *PublicKey) GetEd25519() []byte {
	if x, ok := m.GetSum().(*PublicKey_Ed25519); ok {
		return x.Ed25519
	}
	return nil
}

func (m *PublicKey) GetSecp256K1() []byte {
	if x, ok := m.GetSum().(*PublicKey_Secp256K1); ok {
		return x.Secp256K1
	}
	return nil
}

func (m *PublicKey) GetSecp256K1Uncompressed() []byte {
	if x, ok := m.GetSum().(*PublicKey_Secp256K1Uncompressed); ok {
		return x.Secp256K1Uncompressed
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*PublicKey) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*PublicKey_Ed25519)(nil),
		(*PublicKey_Secp256K1)(nil),
		(*PublicKey_Secp256K1Uncompressed)(nil),
	}
}

func init() {
	proto.RegisterType((*PublicKey)(nil), "tendermint.crypto.PublicKey")
}

func init() { proto.RegisterFile("tendermint/crypto/keys.proto", fileDescriptor_cb048658b234868c) }

var fileDescriptor_cb048658b234868c = []byte{
	// 234 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x92, 0x29, 0x49, 0xcd, 0x4b,
	0x49, 0x2d, 0xca, 0xcd, 0xcc, 0x2b, 0xd1, 0x4f, 0x2e, 0xaa, 0x2c, 0x28, 0xc9, 0xd7, 0xcf, 0x4e,
	0xad, 0x2c, 0xd6, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x12, 0x44, 0xc8, 0xea, 0x41, 0x64, 0xa5,
	0x44, 0xd2, 0xf3, 0xd3, 0xf3, 0xc1, 0xb2, 0xfa, 0x20, 0x16, 0x44, 0xa1, 0xd2, 0x44, 0x46, 0x2e,
	0xce, 0x80, 0xd2, 0xa4, 0x9c, 0xcc, 0x64, 0xef, 0xd4, 0x4a, 0x21, 0x29, 0x2e, 0xf6, 0xd4, 0x14,
	0x23, 0x53, 0x53, 0x43, 0x4b, 0x09, 0x46, 0x05, 0x46, 0x0d, 0x1e, 0x0f, 0x86, 0x20, 0x98, 0x80,
	0x90, 0x1c, 0x17, 0x67, 0x71, 0x6a, 0x72, 0x81, 0x91, 0xa9, 0x59, 0xb6, 0xa1, 0x04, 0x13, 0x54,
	0x16, 0x21, 0x24, 0x64, 0xce, 0x25, 0x06, 0xe7, 0xc4, 0x97, 0xe6, 0x25, 0xe7, 0xe7, 0x16, 0x14,
	0xa5, 0x16, 0x17, 0xa7, 0xa6, 0x48, 0x30, 0x43, 0x15, 0x8b, 0xc2, 0xe5, 0x43, 0x91, 0xa4, 0xad,
	0x38, 0x5e, 0x2c, 0x90, 0x67, 0x7c, 0xb1, 0x50, 0x9e, 0xd1, 0x89, 0x95, 0x8b, 0xb9, 0xb8, 0x34,
	0xd7, 0xc9, 0xef, 0xc4, 0x23, 0x39, 0xc6, 0x0b, 0x8f, 0xe4, 0x18, 0x1f, 0x3c, 0x92, 0x63, 0x9c,
	0xf0, 0x58, 0x8e, 0xe1, 0xc2, 0x63, 0x39, 0x86, 0x1b, 0x8f, 0xe5, 0x18, 0xa2, 0x4c, 0xd2, 0x33,
	0x4b, 0x32, 0x4a, 0x93, 0xf4, 0x92, 0xf3, 0x73, 0xf5, 0x93, 0xf3, 0x73, 0x53, 0x4b, 0x92, 0xd2,
	0x4a, 0x10, 0x0c, 0x88, 0xe7, 0x30, 0xc2, 0x25, 0x89, 0x0d, 0x2c, 0x61, 0x0c, 0x08, 0x00, 0x00,
	0xff, 0xff, 0xf0, 0x8b, 0x85, 0xa8, 0x33, 0x01, 0x00, 0x00,
}

func (this *PublicKey) Compare(that interface{}) int {
	if that == nil {
		if this == nil {
			return 0
		}
		return 1
	}

	that1, ok := that.(*PublicKey)
	if !ok {
		that2, ok := that.(PublicKey)
		if ok {
			that1 = &that2
		} else {
			return 1
		}
	}
	if that1 == nil {
		if this == nil {
			return 0
		}
		return 1
	} else if this == nil {
		return -1
	}
	if that1.Sum == nil {
		if this.Sum != nil {
			return 1
		}
	} else if this.Sum == nil {
		return -1
	} else {
		thisType := -1
		switch this.Sum.(type) {
		case *PublicKey_Ed25519:
			thisType = 0
		case *PublicKey_Secp256K1:
			thisType = 1
		case *PublicKey_Secp256K1Uncompressed:
			thisType = 2
		default:
			panic(fmt.Sprintf("compare: unexpected type %T in oneof", this.Sum))
		}
		that1Type := -1
		switch that1.Sum.(type) {
		case *PublicKey_Ed25519:
			that1Type = 0
		case *PublicKey_Secp256K1:
			that1Type = 1
		case *PublicKey_Secp256K1Uncompressed:
			that1Type = 2
		default:
			panic(fmt.Sprintf("compare: unexpected type %T in oneof", that1.Sum))
		}
		if thisType == that1Type {
			if c := this.Sum.Compare(that1.Sum); c != 0 {
				return c
			}
		} else if thisType < that1Type {
			return -1
		} else if thisType > that1Type {
			return 1
		}
	}
	return 0
}
func (this *PublicKey_Ed25519) Compare(that interface{}) int {
	if that == nil {
		if this == nil {
			return 0
		}
		return 1
	}

	that1, ok := that.(*PublicKey_Ed25519)
	if !ok {
		that2, ok := that.(PublicKey_Ed25519)
		if ok {
			that1 = &that2
		} else {
			return 1
		}
	}
	if that1 == nil {
		if this == nil {
			return 0
		}
		return 1
	} else if this == nil {
		return -1
	}
	if c := bytes.Compare(this.Ed25519, that1.Ed25519); c != 0 {
		return c
	}
	return 0
}
func (this *PublicKey_Secp256K1) Compare(that interface{}) int {
	if that == nil {
		if this == nil {
			return 0
		}
		return 1
	}

	that1, ok := that.(*PublicKey_Secp256K1)
	if !ok {
		that2, ok := that.(PublicKey_Secp256K1)
		if ok {
			that1 = &that2
		} else {
			return 1
		}
	}
	if that1 == nil {
		if this == nil {
			return 0
		}
		return 1
	} else if this == nil {
		return -1
	}
	if c := bytes.Compare(this.Secp256K1, that1.Secp256K1); c != 0 {
		return c
	}
	return 0
}
func (this *PublicKey_Secp256K1Uncompressed) Compare(that interface{}) int {
	if that == nil {
		if this == nil {
			return 0
		}
		return 1
	}

	that1, ok := that.(*PublicKey_Secp256K1Uncompressed)
	if !ok {
		that2, ok := that.(PublicKey_Secp256K1Uncompressed)
		if ok {
			that1 = &that2
		} else {
			return 1
		}
	}
	if that1 == nil {
		if this == nil {
			return 0
		}
		return 1
	} else if this == nil {
		return -1
	}
	if c := bytes.Compare(this.Secp256K1Uncompressed, that1.Secp256K1Uncompressed); c != 0 {
		return c
	}
	return 0
}
func (this *PublicKey) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*PublicKey)
	if !ok {
		that2, ok := that.(PublicKey)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if that1.Sum == nil {
		if this.Sum != nil {
			return false
		}
	} else if this.Sum == nil {
		return false
	} else if !this.Sum.Equal(that1.Sum) {
		return false
	}
	return true
}
func (this *PublicKey_Ed25519) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*PublicKey_Ed25519)
	if !ok {
		that2, ok := that.(PublicKey_Ed25519)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if !bytes.Equal(this.Ed25519, that1.Ed25519) {
		return false
	}
	return true
}
func (this *PublicKey_Secp256K1) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*PublicKey_Secp256K1)
	if !ok {
		that2, ok := that.(PublicKey_Secp256K1)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if !bytes.Equal(this.Secp256K1, that1.Secp256K1) {
		return false
	}
	return true
}
func (this *PublicKey_Secp256K1Uncompressed) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*PublicKey_Secp256K1Uncompressed)
	if !ok {
		that2, ok := that.(PublicKey_Secp256K1Uncompressed)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if !bytes.Equal(this.Secp256K1Uncompressed, that1.Secp256K1Uncompressed) {
		return false
	}
	return true
}
func (m *PublicKey) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *PublicKey) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *PublicKey) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Sum != nil {
		{
			size := m.Sum.Size()
			i -= size
			if _, err := m.Sum.MarshalTo(dAtA[i:]); err != nil {
				return 0, err
			}
		}
	}
	return len(dAtA) - i, nil
}

func (m *PublicKey_Ed25519) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *PublicKey_Ed25519) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	if m.Ed25519 != nil {
		i -= len(m.Ed25519)
		copy(dAtA[i:], m.Ed25519)
		i = encodeVarintKeys(dAtA, i, uint64(len(m.Ed25519)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}
func (m *PublicKey_Secp256K1) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *PublicKey_Secp256K1) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	if m.Secp256K1 != nil {
		i -= len(m.Secp256K1)
		copy(dAtA[i:], m.Secp256K1)
		i = encodeVarintKeys(dAtA, i, uint64(len(m.Secp256K1)))
		i--
		dAtA[i] = 0x12
	}
	return len(dAtA) - i, nil
}
func (m *PublicKey_Secp256K1Uncompressed) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *PublicKey_Secp256K1Uncompressed) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	if m.Secp256K1Uncompressed != nil {
		i -= len(m.Secp256K1Uncompressed)
		copy(dAtA[i:], m.Secp256K1Uncompressed)
		i = encodeVarintKeys(dAtA, i, uint64(len(m.Secp256K1Uncompressed)))
		i--
		dAtA[i] = 0x1a
	}
	return len(dAtA) - i, nil
}
func encodeVarintKeys(dAtA []byte, offset int, v uint64) int {
	offset -= sovKeys(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *PublicKey) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Sum != nil {
		n += m.Sum.Size()
	}
	return n
}

func (m *PublicKey_Ed25519) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Ed25519 != nil {
		l = len(m.Ed25519)
		n += 1 + l + sovKeys(uint64(l))
	}
	return n
}
func (m *PublicKey_Secp256K1) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Secp256K1 != nil {
		l = len(m.Secp256K1)
		n += 1 + l + sovKeys(uint64(l))
	}
	return n
}
func (m *PublicKey_Secp256K1Uncompressed) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Secp256K1Uncompressed != nil {
		l = len(m.Secp256K1Uncompressed)
		n += 1 + l + sovKeys(uint64(l))
	}
	return n
}

func sovKeys(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozKeys(x uint64) (n int) {
	return sovKeys(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *PublicKey) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowKeys
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: PublicKey: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: PublicKey: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Ed25519", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowKeys
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthKeys
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthKeys
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			v := make([]byte, postIndex-iNdEx)
			copy(v, dAtA[iNdEx:postIndex])
			m.Sum = &PublicKey_Ed25519{v}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Secp256K1", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowKeys
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthKeys
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthKeys
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			v := make([]byte, postIndex-iNdEx)
			copy(v, dAtA[iNdEx:postIndex])
			m.Sum = &PublicKey_Secp256K1{v}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Secp256K1Uncompressed", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowKeys
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthKeys
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthKeys
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			v := make([]byte, postIndex-iNdEx)
			copy(v, dAtA[iNdEx:postIndex])
			m.Sum = &PublicKey_Secp256K1Uncompressed{v}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipKeys(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthKeys
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipKeys(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowKeys
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowKeys
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowKeys
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthKeys
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupKeys
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthKeys
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthKeys        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowKeys          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupKeys = fmt.Errorf("proto: unexpected end of group")
)
