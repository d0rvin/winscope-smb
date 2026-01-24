package v2

import (
	"github.com/d0rvin/winscope-smb/pkg/protocol/gss"
)

const ProtocolSmb2 = "\xFESMB"

const (
	CommandNegotiate uint16 = iota
	CommandSessionSetup
)

const (
	DialectSmb_2_1 = 0x0210
)

const (
	_ uint16 = iota
	SecurityModeSigningEnabled
	SecurityModeSigningRequired
)

type Header struct {
	ProtocolID    []byte `smb:"fixed:4"`
	StructureSize uint16
	CreditCharge  uint16
	Status        uint32
	Command       uint16
	Credits       uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32
	TreeID        uint32
	SessionID     uint64
	Signature     []byte `smb:"fixed:16"`
}

func newHeader() Header {
	return Header{
		ProtocolID:    []byte(ProtocolSmb2),
		StructureSize: 64,
		Signature:     make([]byte, 16),
	}
}

type NegotiateReq struct {
	Header
	StructureSize   uint16
	DialectCount    uint16 `smb:"count:Dialects"`
	SecurityMode    uint16
	Reserved        uint16
	Capabilities    uint32
	ClientGuid      []byte `smb:"fixed:16"`
	ClientStartTime uint64
	Dialects        []uint16
}

func NewNegotiateReq(messageID uint64) NegotiateReq {
	header := newHeader()
	header.Command = CommandNegotiate
	header.CreditCharge = 1

	dialects := []uint16{
		uint16(DialectSmb_2_1),
	}
	return NegotiateReq{
		Header:        header,
		StructureSize: 36,
		DialectCount:  uint16(len(dialects)),
		SecurityMode:  SecurityModeSigningEnabled,
		ClientGuid:    make([]byte, 16),
		Dialects:      dialects,
	}
}

type NegotiateRes struct {
	Header
	StructureSize        uint16
	SecurityMode         uint16
	DialectRevision      uint16
	Reserved             uint16
	ServerGuid           []byte `smb:"fixed:16"`
	Capabilities         uint32
	MaxTransactSize      uint32
	MaxReadSize          uint32
	MaxWriteSize         uint32
	SystemTime           uint64
	ServerStartTime      uint64
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	Reserved2            uint32
	SecurityBlob         *gss.NegTokenInit
}

func NewNegotiateRes() NegotiateRes {
	return NegotiateRes{
		Header:       newHeader(),
		ServerGuid:   make([]byte, 16),
		SecurityBlob: &gss.NegTokenInit{},
	}
}

type SessionSetup1Req struct {
	Header
	StructureSize        uint16
	Flags                byte
	SecurityMode         byte
	Capabilities         uint32
	Channel              uint32
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	PreviousSessionID    uint64
	SecurityBlob         *gss.NegTokenInit
}

type SessionSetup1Res struct {
	Header
	StructureSize        uint16
	Flags                uint16
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	SecurityBlob         *gss.NegTokenResp
}

func NewSessionSetup1Res() (SessionSetup1Res, error) {
	resp, err := gss.NewNegTokenResp()
	if err != nil {
		return SessionSetup1Res{}, err
	}
	ret := SessionSetup1Res{
		Header:       newHeader(),
		SecurityBlob: &resp,
	}
	return ret, nil
}
