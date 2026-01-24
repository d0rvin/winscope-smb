package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/d0rvin/winscope-smb/pkg/encoding"
)

const Signature = "NTLMSSP\x00"

const (
	_ uint32 = iota
	TypeNtLmNegotiate
	TypeNtLmChallenge
	TypeNtLmAuthenticate
)

const (
	FlgNegUnicode uint32 = 1 << iota
	FlgNegOEM
	FlgNegRequestTarget
	FlgNegReserved10
	FlgNegSign
	FlgNegSeal
	FlgNegDatagram
	FlgNegLmKey
	FlgNegReserved9
	FlgNegNtLm
	FlgNegReserved8
	FlgNegAnonymous
	FlgNegOEMDomainSupplied
	FlgNegOEMWorkstationSupplied
	FlgNegReserved7
	FlgNegAlwaysSign
	FlgNegTargetTypeDomain
	FlgNegTargetTypeServer
	FlgNegReserved6
	FlgNegExtendedSessionSecurity
	FlgNegIdentify
	FlgNegReserved5
	FlgNegRequestNonNtSessionKey
	FlgNegTargetInfo
	FlgNegReserved4
	FlgNegVersion
	FlgNegReserved3
	FlgNegReserved2
	FlgNegReserved1
	FlgNeg128
	FlgNegKeyExch
	FlgNeg56
)

const (
	AvEOL             = 0x0000
	AvNBComputerName  = 0x0001
	AvNBDomainName    = 0x0002
	AvDNSComputerName = 0x0003
	AvDNSDomainName   = 0x0004
	AvDNSTreeName     = 0x0005
	AvFlags           = 0x0006
	AvTimestamp       = 0x0007
	AvSingleHost      = 0x0008
	AvTargetName      = 0x0009
	AvChannelBindings = 0x000A
)

type Header struct {
	Signature   []byte `smb:"fixed:8"`
	MessageType uint32
}

type Challenge struct {
	Header
	TargetNameLen          uint16 `smb:"len:TargetName"`
	TargetNameMaxLen       uint16 `smb:"len:TargetName"`
	TargetNameBufferOffset uint32 `smb:"offset:TargetName"`
	NegotiateFlags         uint32
	ServerChallenge        uint64
	Reserved               uint64
	TargetInfoLen          uint16 `smb:"len:TargetInfo"`
	TargetInfoMaxLen       uint16 `smb:"len:TargetInfo"`
	TargetInfoBufferOffset uint32 `smb:"offset:TargetInfo"`
	Version                *Version
	TargetName             []byte
	TargetInfo             *AvPairSlice
}

type Version struct {
	Major    uint8
	Minor    uint8
	Build    uint16
	Reserved []byte `smb:"fixed:3"`
	Revision uint8
}

func (v *Version) ParseToOS() (string, bool) {
	fullVersion := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Build)
	if os, ok := fullVersionOSMap[fullVersion]; ok {
		return os, ok
	}

	majorMinorVersion := fmt.Sprintf("%d.%d", v.Major, v.Minor)
	os, ok := majorMinorVersionOSMap[majorMinorVersion]
	return os, ok
}

type AvPair struct {
	AvID  uint16
	AvLen uint16 `smb:"len:Value"`
	Value []byte
}

type AvDetail struct {
	NBComputerName  string
	NBDomainName    string
	DNSComputerName string
	DNSDomainName   string
	DNSTreeName     string
	Time            time.Time
	TargetName      string
}

func (p AvPair) Size() uint64 {
	return uint64(binary.Size(p.AvID) + binary.Size(p.AvLen) + int(p.AvLen))
}

type AvPairSlice []AvPair

func (s *AvPairSlice) MarshalBinary(meta *encoding.Metadata) ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)
	for _, pair := range *s {
		buf, err := encoding.Marshal(pair)
		if err != nil {
			return nil, err
		}
		if err := binary.Write(w, binary.LittleEndian, buf); err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}

func (s *AvPairSlice) UnmarshalBinary(buf []byte, meta *encoding.Metadata) (int, error) {
	if meta == nil {
		return 0, fmt.Errorf("missing metadata for AvPairSlice unmarshal")
	}
	slice := []AvPair{}
	l, ok := meta.Lens[meta.CurrField]
	if !ok {
		return 0, fmt.Errorf("missing unmarshal field '%s' length", meta.CurrField)
	}
	o, ok := meta.Offsets[meta.CurrField]
	if !ok {
		return 0, fmt.Errorf("missing unmarshal field '%s' offset", meta.CurrField)
	}
	for i := l; i > 0; {
		var avPair AvPair
		err := encoding.Unmarshal(meta.ParentBuf[o:o+i], &avPair)
		if err != nil {
			return 0, err
		}
		slice = append(slice, avPair)
		size := avPair.Size()
		o += int(size)
		i -= int(size)
	}
	*s = slice
	offset := o - meta.Offsets[meta.CurrField]
	return offset, nil
}

func (s *AvPairSlice) Parse() *AvDetail {
	var ret AvDetail
	for _, v := range *s {
		visibleVal := strings.Map(func(r rune) rune {
			if unicode.IsGraphic(r) {
				return r
			}
			return -1
		}, string(v.Value))
		switch v.AvID {
		case AvNBComputerName:
			ret.NBComputerName = visibleVal
		case AvNBDomainName:
			ret.NBDomainName = visibleVal
		case AvDNSComputerName:
			ret.DNSComputerName = visibleVal
		case AvDNSDomainName:
			ret.DNSDomainName = visibleVal
		case AvDNSTreeName:
			ret.DNSTreeName = visibleVal
		case AvTimestamp:
			if v.AvLen != 8 {
				continue
			}
			ret.Time = FileTimeToSystemTime(v.Value)
		case AvTargetName:
			ret.TargetName = visibleVal
		case AvEOL:
			return &ret
		}
	}
	return &ret
}

func NewChallenge() Challenge {
	return Challenge{
		Header: Header{
			Signature:   []byte(Signature),
			MessageType: TypeNtLmChallenge,
		},
		NegotiateFlags: FlgNeg56 |
			FlgNeg128 |
			FlgNegVersion |
			FlgNegTargetInfo |
			FlgNegExtendedSessionSecurity |
			FlgNegTargetTypeServer |
			FlgNegNtLm |
			FlgNegRequestTarget |
			FlgNegUnicode,
	}
}

type Negotiate struct {
	Header
	NegotiateFlags          uint32
	DomainNameLen           uint16 `smb:"len:DomainName"`
	DomainNameMaxLen        uint16 `smb:"len:DomainName"`
	DomainNameBufferOffset  uint32 `smb:"offset:DomainName"`
	WorkstationLen          uint16 `smb:"len:Workstation"`
	WorkstationMaxLen       uint16 `smb:"len:Workstation"`
	WorkstationBufferOffset uint32 `smb:"offset:Workstation"`
	DomainName              []byte
	Workstation             []byte
}

func NewNegotiate(domainName, workstation string) Negotiate {
	return Negotiate{
		Header: Header{
			Signature:   []byte(Signature),
			MessageType: TypeNtLmNegotiate,
		},
		NegotiateFlags: FlgNeg56 |
			FlgNeg128 |
			FlgNegTargetInfo |
			FlgNegExtendedSessionSecurity |
			FlgNegOEMDomainSupplied |
			FlgNegNtLm |
			FlgNegRequestTarget |
			FlgNegUnicode,
		DomainName:  []byte(domainName),
		Workstation: []byte(workstation),
	}
}
