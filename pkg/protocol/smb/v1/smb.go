package v1

import (
	"github.com/d0rvin/winscope-smb/pkg/protocol/gss"
)

const ProtocolSmb = "\xFFSMB"

const (
	CommandNegotiate        = 0x72
	CommandSessionSetUpAndX = 0x73
)

const (
	FlagsCaseInsensitive    = 0x08
	FlagsCanonicalizedPaths = 0x10
)

const (
	Flags2LongNames        = 0x0001
	Flags2ExtendedSecurity = 0x0800
	Flags2NTStatus         = 0x4000
)

const (
	CapUnicode          = 0x00000004
	CapStatus32         = 0x00000040
	CapLargeReadX       = 0x00004000
	CapLargeWriteX      = 0x00008000
	CapExtendedSecurity = 0x80000000
)

var (
	DialectSmb1 = []byte{
		'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2',
	}
)

type Header struct {
	Protocol         []byte `smb:"fixed:4"`
	Command          uint8
	Status           uint32
	Flags            uint8
	Flags2           uint16
	PIDHigh          uint16
	SecurityFeatures []byte `smb:"fixed:8"`
	Reserved         uint16
	TID              uint16
	PIDLow           uint16
	UID              uint16
	MID              uint16
}

func newHeader() Header {
	return Header{
		Protocol:         []byte(ProtocolSmb),
		SecurityFeatures: make([]byte, 8),
	}
}

type NegotiateReq struct {
	Header
	WordCount uint8
	ByteCount uint16
	Dialects  []byte
}

func NewNegotiateReq() NegotiateReq {
	header := newHeader()
	header.Command = CommandNegotiate
	header.Flags = FlagsCaseInsensitive | FlagsCanonicalizedPaths
	header.Flags2 = Flags2LongNames | Flags2ExtendedSecurity | Flags2NTStatus
	header.TID = 0xffff
	header.PIDLow = 0xc744

	dialects := [][]byte{DialectSmb1}
	dialectsBytes := []byte{}
	for _, v := range dialects {
		dialectsBytes = append(dialectsBytes, 0x02)
		dialectsBytes = append(dialectsBytes, v...)
		dialectsBytes = append(dialectsBytes, 0x00)
	}
	return NegotiateReq{
		Header:    header,
		ByteCount: uint16(len(dialectsBytes)),
		Dialects:  dialectsBytes,
	}
}

type NegotiateRes struct {
	Header
	WordCount       uint8
	DialectIndex    uint16
	SecurityMode    uint8
	MaxMpxCount     uint16
	MaxNumberVcs    uint16
	MaxBufferSize   uint32
	MaxRawSize      uint32
	SessionKey      uint32
	Capabilities    uint32
	SystemTime      uint64
	SystemTimeZone  uint16
	ChallengeLength uint8
	ByteCount       uint16
	GUID            []byte `smb:"fixed:16"`
	SecurityBlob    *gss.NegTokenInit
}

func NewNegotiateRes() NegotiateRes {
	return NegotiateRes{
		Header:       newHeader(),
		SecurityBlob: &gss.NegTokenInit{},
	}
}

type SessionSetupAndXReq struct {
	Header
	WordCount          uint8
	AndXCommand        uint8
	AndXReserved       uint8
	AndXOffset         uint16
	MaxBufferSize      uint16
	MaxMpxCount        uint16
	VcNumber           uint16
	SessionKey         uint32
	SecurityBlobLength uint16 `smb:"len:SecurityBlob"`
	Reserved           uint32
	Capabilities       uint32
	ByteCount          uint16
	SecurityBlob       *gss.NegTokenInit
	NativeOS           []byte
	NativeLanMan       []byte
}

type SessionSetupAndXRes struct {
	Header
	WordCount          uint8
	AndXCommand        uint8
	AndXReserved       uint8
	AndXOffset         uint16
	Action             uint16
	SecurityBlobLength uint16 `smb:"len:SecurityBlob"`
	ByteCount          uint16
	SecurityBlob       *gss.NegTokenResp
	Pad                []byte `smb:"pad"`
	NativeOS           string
	NativeLanMan       string
}

func NewSessionSetupAndXRes() (SessionSetupAndXRes, error) {
	resp, err := gss.NewNegTokenResp()
	if err != nil {
		return SessionSetupAndXRes{}, err
	}
	ret := SessionSetupAndXRes{
		Header:       newHeader(),
		SecurityBlob: &resp,
	}
	return ret, nil
}
