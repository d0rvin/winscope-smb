package encoding_test

import (
	"encoding/asn1"
	"testing"

	"github.com/d0rvin/winscope-smb/pkg/protocol/gss"
	"github.com/d0rvin/winscope-smb/pkg/protocol/ntlmssp"

	"github.com/d0rvin/winscope-smb/pkg/encoding"
	"github.com/stretchr/testify/assert"
)

type TestDecodeUint8 struct {
	Value uint8
}

func TestUnmarshal_Uint8(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    uint8
		wantErr bool
	}{
		{
			name:    "zero",
			buf:     []byte{0x00},
			want:    0,
			wantErr: false,
		},
		{
			name:    "max",
			buf:     []byte{0xff},
			want:    255,
			wantErr: false,
		},
		{
			name:    "middle",
			buf:     []byte{0x80},
			want:    128,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TestDecodeUint8
			err := encoding.Unmarshal(tt.buf, &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got.Value)
			}
		})
	}
}

type TestDecodeUint16 struct {
	Value uint16
}

func TestUnmarshal_Uint16(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    uint16
		wantErr bool
	}{
		{
			name:    "zero",
			buf:     []byte{0x00, 0x00},
			want:    0,
			wantErr: false,
		},
		{
			name:    "max",
			buf:     []byte{0xff, 0xff},
			want:    65535,
			wantErr: false,
		},
		{
			name:    "middle",
			buf:     []byte{0x00, 0x01},
			want:    256,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TestDecodeUint16
			err := encoding.Unmarshal(tt.buf, &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got.Value)
			}
		})
	}
}

type TestDecodeUint32 struct {
	Value uint32
}

func TestUnmarshal_Uint32(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    uint32
		wantErr bool
	}{
		{
			name:    "zero",
			buf:     []byte{0x00, 0x00, 0x00, 0x00},
			want:    0,
			wantErr: false,
		},
		{
			name:    "max",
			buf:     []byte{0xff, 0xff, 0xff, 0xff},
			want:    4294967295,
			wantErr: false,
		},
		{
			name:    "middle",
			buf:     []byte{0x00, 0x00, 0x01, 0x00},
			want:    65536,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TestDecodeUint32
			err := encoding.Unmarshal(tt.buf, &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got.Value)
			}
		})
	}
}

type TestDecodeUint64 struct {
	Value uint64
}

func TestUnmarshal_Uint64(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    uint64
		wantErr bool
	}{
		{
			name:    "zero",
			buf:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want:    0,
			wantErr: false,
		},
		{
			name:    "max",
			buf:     []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			want:    18446744073709551615,
			wantErr: false,
		},
		{
			name:    "middle",
			buf:     []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
			want:    4294967296,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TestDecodeUint64
			err := encoding.Unmarshal(tt.buf, &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got.Value)
			}
		})
	}
}

type TestDecodeString struct {
	Value string
}

func TestUnmarshal_String(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    string
		wantErr bool
	}{
		{
			name:    "empty",
			buf:     []byte{0x00},
			want:    "",
			wantErr: false,
		},
		{
			name:    "simple",
			buf:     []byte{'h', 'i', 0x00},
			want:    "hi",
			wantErr: false,
		},
		{
			name:    "with null bytes",
			buf:     []byte{'h', 'e', 'l', 'l', 'o', 0x00},
			want:    "hello",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TestDecodeString
			err := encoding.Unmarshal(tt.buf, &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got.Value)
			}
		})
	}
}

type TestDecodeStructWithLenField2 struct {
	DataLen uint16 `smb:"len:Data"`
	Data    []byte
}

func TestUnmarshal_Slice_Uint8(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    []byte
		wantErr bool
	}{
		{
			name:    "empty",
			buf:     []byte{0x00, 0x00},
			want:    []byte{},
			wantErr: false,
		},
		{
			name:    "single",
			buf:     []byte{0x01, 0x00, 0x01},
			want:    []byte{0x01},
			wantErr: false,
		},
		{
			name:    "multiple",
			buf:     []byte{0x04, 0x00, 0x01, 0x02, 0x03, 0x04},
			want:    []byte{0x01, 0x02, 0x03, 0x04},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TestDecodeStructWithLenField2
			err := encoding.Unmarshal(tt.buf, &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got.Data)
			}
		})
	}
}

type TestDecodeStruct struct {
	A uint8
	B uint16
	C uint32
}

func TestUnmarshal_Struct(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    TestDecodeStruct
		wantErr bool
	}{
		{
			name: "basic",
			buf:  []byte{0x01, 0x03, 0x02, 0x07, 0x06, 0x05, 0x04},
			want: TestDecodeStruct{
				A: 0x01,
				B: 0x0203,
				C: 0x04050607,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TestDecodeStruct
			err := encoding.Unmarshal(tt.buf, &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

type TestDecodeStructWithFixedSlice struct {
	A uint8
	B []byte `smb:"fixed:4"`
	C uint16
}

func TestUnmarshal_StructWithFixedSlice(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    TestDecodeStructWithFixedSlice
		wantErr bool
	}{
		{
			name: "basic",
			buf:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x06},
			want: TestDecodeStructWithFixedSlice{
				A: 0x01,
				B: []byte{0x02, 0x03, 0x04, 0x05},
				C: 0x0607,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TestDecodeStructWithFixedSlice
			err := encoding.Unmarshal(tt.buf, &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

type TestDecodeStructWithLenField struct {
	DataLen uint16 `smb:"len:Data"`
	Data    []byte
}

func TestUnmarshal_StructWithLenField(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    TestDecodeStructWithLenField
		wantErr bool
	}{
		{
			name: "basic",
			buf:  []byte{0x04, 0x00, 0x01, 0x02, 0x03, 0x04},
			want: TestDecodeStructWithLenField{
				Data: []byte{0x01, 0x02, 0x03, 0x04},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TestDecodeStructWithLenField
			err := encoding.Unmarshal(tt.buf, &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want.Data, got.Data)
			}
		})
	}
}

type TestDecodeCustomMarshal struct {
	Value uint16
}

func (t *TestDecodeCustomMarshal) MarshalBinary(meta *encoding.Metadata) ([]byte, error) {
	buf := make([]byte, 2)
	buf[0] = byte(t.Value & 0xFF)
	buf[1] = byte((t.Value >> 8) & 0xFF)
	return buf, nil
}

func (t *TestDecodeCustomMarshal) UnmarshalBinary(buf []byte, meta *encoding.Metadata) (int, error) {
	t.Value = uint16(buf[0]) | uint16(buf[1])<<8
	return 2, nil
}

func TestUnmarshal_CustomMarshal(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    TestDecodeCustomMarshal
		wantErr bool
	}{
		{
			name:    "custom",
			buf:     []byte{0x02, 0x01},
			want:    TestDecodeCustomMarshal{Value: 0x0102},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TestDecodeCustomMarshal
			err := encoding.Unmarshal(tt.buf, &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestUnmarshal_NegTokenInit(t *testing.T) {
	ntlmoid, _ := gss.ObjectIDStrToInt(gss.NtLmSSPMechTypeOid)
	spnegoOID, _ := gss.ObjectIDStrToInt(gss.SpnegoOid)

	tests := []struct {
		name    string
		buf     []byte
		want    gss.NegTokenInit
		wantErr bool
	}{
		{
			name: "basic",
			buf:  []byte{0x60, 0x1c, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x12, 0x30, 0x10, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a},
			want: gss.NegTokenInit{
				OID: spnegoOID,
				Data: gss.NegTokenInitData{
					MechTypes: []asn1.ObjectIdentifier{ntlmoid},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got gss.NegTokenInit
			err := encoding.Unmarshal(tt.buf, &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want.OID, got.OID)
				assert.Equal(t, tt.want.Data.MechTypes[0], got.Data.MechTypes[0])
			}
		})
	}
}

func TestUnmarshal_NegTokenResp(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    gss.NegTokenResp
		wantErr bool
	}{
		{
			name: "basic",
			buf:  []byte{0xa1, 0x0e, 0x30, 0x0c, 0xa0, 0x03, 0x0a, 0x01, 0x01, 0xa2, 0x05, 0x04, 0x03, 0x01, 0x02, 0x03},
			want: gss.NegTokenResp{
				State:         1,
				ResponseToken: []byte{0x01, 0x02, 0x03},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got gss.NegTokenResp
			err := encoding.Unmarshal(tt.buf, &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want.State, got.State)
				assert.Equal(t, tt.want.ResponseToken, got.ResponseToken)
			}
		})
	}
}

func TestUnmarshal_AvPairSlice(t *testing.T) {
	type TestAvPairSliceStruct struct {
		Len    uint16 `smb:"len:Data"`
		Offset uint32 `smb:"offset:Data"`
		Data   ntlmssp.AvPairSlice
	}

	tests := []struct {
		name    string
		buf     []byte
		want    ntlmssp.AvPairSlice
		wantErr bool
	}{
		{
			name: "single",
			buf: []byte{
				0x0c, 0x00,
				0x06, 0x00, 0x00, 0x00,
				0x01, 0x00, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			},
			want: ntlmssp.AvPairSlice{
				{AvID: ntlmssp.AvNBComputerName, AvLen: 8, Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
			},
			wantErr: false,
		},
		{
			name: "multiple",
			buf: []byte{
				0x0c, 0x00,
				0x06, 0x00, 0x00, 0x00,
				0x01, 0x00, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00,
			},
			want: ntlmssp.AvPairSlice{
				{AvID: ntlmssp.AvNBComputerName, AvLen: 4, Value: []byte{0x01, 0x02, 0x03, 0x04}},
				{AvID: ntlmssp.AvEOL, AvLen: 0, Value: []byte{}},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TestAvPairSliceStruct
			err := encoding.Unmarshal(tt.buf, &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, len(tt.want), len(got.Data))
				for i := range tt.want {
					assert.Equal(t, tt.want[i].AvID, got.Data[i].AvID)
					assert.Equal(t, tt.want[i].AvLen, got.Data[i].AvLen)
					assert.Equal(t, tt.want[i].Value, got.Data[i].Value)
				}
			}
		})
	}
}
