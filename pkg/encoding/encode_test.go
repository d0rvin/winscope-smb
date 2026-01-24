package encoding_test

import (
	"encoding/asn1"
	"encoding/binary"
	"testing"

	"github.com/d0rvin/winscope-smb/pkg/protocol/gss"
	"github.com/d0rvin/winscope-smb/pkg/protocol/ntlmssp"

	"github.com/d0rvin/winscope-smb/pkg/encoding"
	"github.com/stretchr/testify/assert"
)

func TestMarshal_Uint8(t *testing.T) {
	tests := []struct {
		name    string
		v       uint8
		want    []byte
		wantErr bool
	}{
		{
			name:    "zero",
			v:       0,
			want:    []byte{0x00},
			wantErr: false,
		},
		{
			name:    "max",
			v:       255,
			want:    []byte{0xff},
			wantErr: false,
		},
		{
			name:    "middle",
			v:       128,
			want:    []byte{0x80},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encoding.Marshal(tt.v)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestMarshal_Uint16(t *testing.T) {
	tests := []struct {
		name    string
		v       uint16
		want    []byte
		wantErr bool
	}{
		{
			name:    "zero",
			v:       0,
			want:    []byte{0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "max",
			v:       65535,
			want:    []byte{0xff, 0xff},
			wantErr: false,
		},
		{
			name:    "middle",
			v:       256,
			want:    []byte{0x00, 0x01},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encoding.Marshal(tt.v)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestMarshal_Uint32(t *testing.T) {
	tests := []struct {
		name    string
		v       uint32
		want    []byte
		wantErr bool
	}{
		{
			name:    "zero",
			v:       0,
			want:    []byte{0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "max",
			v:       4294967295,
			want:    []byte{0xff, 0xff, 0xff, 0xff},
			wantErr: false,
		},
		{
			name:    "middle",
			v:       65536,
			want:    []byte{0x00, 0x00, 0x01, 0x00},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encoding.Marshal(tt.v)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestMarshal_Uint64(t *testing.T) {
	tests := []struct {
		name    string
		v       uint64
		want    []byte
		wantErr bool
	}{
		{
			name:    "zero",
			v:       0,
			want:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "max",
			v:       18446744073709551615,
			want:    []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			wantErr: false,
		},
		{
			name:    "middle",
			v:       4294967296,
			want:    []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encoding.Marshal(tt.v)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestMarshal_Slice_Uint8(t *testing.T) {
	tests := []struct {
		name    string
		v       []uint8
		want    []byte
		wantErr bool
	}{
		{
			name:    "empty",
			v:       []uint8{},
			want:    []byte{},
			wantErr: false,
		},
		{
			name:    "single",
			v:       []uint8{0x01},
			want:    []byte{0x01},
			wantErr: false,
		},
		{
			name:    "multiple",
			v:       []uint8{0x01, 0x02, 0x03, 0x04},
			want:    []byte{0x01, 0x02, 0x03, 0x04},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encoding.Marshal(tt.v)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, got, len(tt.want))
				if len(tt.want) > 0 {
					assert.Equal(t, tt.want, got)
				}
			}
		})
	}
}

func TestMarshal_Slice_Uint16(t *testing.T) {
	tests := []struct {
		name    string
		v       []uint16
		want    []byte
		wantErr bool
	}{
		{
			name:    "empty",
			v:       []uint16{},
			want:    []byte{},
			wantErr: false,
		},
		{
			name:    "single",
			v:       []uint16{0x0102},
			want:    []byte{0x02, 0x01},
			wantErr: false,
		},
		{
			name:    "multiple",
			v:       []uint16{0x0102, 0x0304, 0x0506},
			want:    []byte{0x02, 0x01, 0x04, 0x03, 0x06, 0x05},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encoding.Marshal(tt.v)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, got, len(tt.want))
				if len(tt.want) > 0 {
					assert.Equal(t, tt.want, got)
				}
			}
		})
	}
}

type TestStruct struct {
	A uint8
	B uint16
	C uint32
}

func TestMarshal_Struct(t *testing.T) {
	tests := []struct {
		name    string
		v       TestStruct
		want    []byte
		wantErr bool
	}{
		{
			name: "basic",
			v: TestStruct{
				A: 0x01,
				B: 0x0203,
				C: 0x04050607,
			},
			want:    []byte{0x01, 0x03, 0x02, 0x07, 0x06, 0x05, 0x04},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encoding.Marshal(tt.v)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

type TestStructWithFixedSlice struct {
	A uint8
	B []byte `smb:"fixed:4"`
	C uint16
}

func TestMarshal_StructWithFixedSlice(t *testing.T) {
	tests := []struct {
		name    string
		v       TestStructWithFixedSlice
		want    []byte
		wantErr bool
	}{
		{
			name: "basic",
			v: TestStructWithFixedSlice{
				A: 0x01,
				B: []byte{0x02, 0x03, 0x04, 0x05},
				C: 0x0607,
			},
			want:    []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x06},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encoding.Marshal(tt.v)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

type TestStructWithLenField struct {
	DataLen uint16 `smb:"len:Data"`
	Data    []byte
}

func TestMarshal_StructWithLenField(t *testing.T) {
	tests := []struct {
		name    string
		v       TestStructWithLenField
		want    []byte
		wantErr bool
	}{
		{
			name: "basic",
			v: TestStructWithLenField{
				Data: []byte{0x01, 0x02, 0x03, 0x04},
			},
			want:    []byte{0x04, 0x00, 0x01, 0x02, 0x03, 0x04},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encoding.Marshal(tt.v)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

type TestCustomMarshal struct {
	Value uint16
}

func (t *TestCustomMarshal) MarshalBinary(meta *encoding.Metadata) ([]byte, error) {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, t.Value)
	return buf, nil
}

func (t *TestCustomMarshal) UnmarshalBinary(buf []byte, meta *encoding.Metadata) (int, error) {
	t.Value = binary.LittleEndian.Uint16(buf)
	return binary.Size(t.Value), nil
}

func TestMarshal_CustomMarshal(t *testing.T) {
	tests := []struct {
		name    string
		v       TestCustomMarshal
		want    []byte
		wantErr bool
	}{
		{
			name: "custom",
			v: TestCustomMarshal{
				Value: 0x0102,
			},
			want:    []byte{0x02, 0x01},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encoding.Marshal(tt.v)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestMarshal_NegTokenInit(t *testing.T) {
	ntlmoid, _ := gss.ObjectIDStrToInt(gss.NtLmSSPMechTypeOid)
	spnegoOID, _ := gss.ObjectIDStrToInt(gss.SpnegoOid)

	tests := []struct {
		name    string
		v       *gss.NegTokenInit
		want    []byte
		wantErr bool
	}{
		{
			name: "basic",
			v: &gss.NegTokenInit{
				OID: spnegoOID,
				Data: gss.NegTokenInitData{
					MechTypes: []asn1.ObjectIdentifier{ntlmoid},
				},
			},
			want:    []byte{0x60, 0x1c, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x12, 0x30, 0x10, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encoding.Marshal(tt.v)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestMarshal_NegTokenResp(t *testing.T) {
	tests := []struct {
		name    string
		v       *gss.NegTokenResp
		want    []byte
		wantErr bool
	}{
		{
			name: "basic",
			v: &gss.NegTokenResp{
				State:         1,
				ResponseToken: []byte{0x01, 0x02, 0x03},
			},
			want:    []byte{0xa1, 0x0e, 0x30, 0x0c, 0xa0, 0x03, 0x0a, 0x01, 0x01, 0xa2, 0x05, 0x04, 0x03, 0x01, 0x02, 0x03},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encoding.Marshal(tt.v)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestMarshal_AvPairSlice(t *testing.T) {
	tests := []struct {
		name    string
		v       *ntlmssp.AvPairSlice
		want    []byte
		wantErr bool
	}{
		{
			name: "empty",
			v:    &ntlmssp.AvPairSlice{},
			want: []byte{},
		},
		{
			name: "single",
			v: &ntlmssp.AvPairSlice{
				{AvID: ntlmssp.AvNBComputerName, Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
			},
			want:    []byte{0x01, 0x00, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			wantErr: false,
		},
		{
			name: "multiple",
			v: &ntlmssp.AvPairSlice{
				{AvID: ntlmssp.AvNBComputerName, Value: []byte{0x01, 0x02, 0x03, 0x04}},
				{AvID: ntlmssp.AvEOL, Value: []byte{}},
			},
			want:    []byte{0x01, 0x00, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encoding.Marshal(tt.v)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, got, len(tt.want))
				if len(tt.want) > 0 {
					assert.Equal(t, tt.want, got)
				}
			}
		})
	}
}
