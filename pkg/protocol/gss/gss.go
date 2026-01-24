package gss

import (
	"encoding/asn1"
	"errors"

	"github.com/d0rvin/winscope-smb/pkg/encoding"
)

const SpnegoOid = "1.3.6.1.5.5.2"
const NtLmSSPMechTypeOid = "1.3.6.1.4.1.311.2.2.10"

const (
	GssStateAcceptCompleted  = 0
	GssStateAcceptIncomplete = 1
	GssStateReject           = 2
	GssStateRequestMic       = 3
)

type NegTokenInitData struct {
	MechTypes    []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags     asn1.BitString          `asn1:"explicit,optional,omitempty,tag:1"`
	MechToken    []byte                  `asn1:"explicit,optional,omitempty,tag:2"`
	MechTokenMIC []byte                  `asn1:"explicit,optional,omitempty,tag:3"`
}

type NegTokenInit struct {
	OID  asn1.ObjectIdentifier
	Data NegTokenInitData `asn1:"explicit"`
}

func NewNegTokenInit() (NegTokenInit, error) {
	oid, err := ObjectIDStrToInt(SpnegoOid)
	if err != nil {
		return NegTokenInit{}, err
	}
	ntlmoid, err := ObjectIDStrToInt(NtLmSSPMechTypeOid)
	if err != nil {
		return NegTokenInit{}, err
	}
	return NegTokenInit{
		OID: oid,
		Data: NegTokenInitData{
			MechTypes:    []asn1.ObjectIdentifier{ntlmoid},
			ReqFlags:     asn1.BitString{},
			MechToken:    []byte{},
			MechTokenMIC: []byte{},
		},
	}, nil
}

func (n *NegTokenInit) MarshalBinary(meta *encoding.Metadata) ([]byte, error) {
	buf, err := asn1.Marshal(*n)
	if err != nil {
		return nil, err
	}

	// When marshalling struct, asn1 uses 30 (sequence) tag by default.
	// Override to set 60 (application) to remain consistent with GSS/SMB
	if len(buf) == 0 {
		return nil, errors.New("marshaled data is empty")
	}
	buf[0] = 0x60
	return buf, nil
}

func (n *NegTokenInit) UnmarshalBinary(buf []byte, meta *encoding.Metadata) (int, error) {
	data := NegTokenInit{}
	rest, err := asn1.UnmarshalWithParams(buf, &data, "application")
	if err != nil {
		return 0, err
	}
	*n = data
	offset := len(buf) - len(rest)
	return offset, nil
}

// gsswrapped used to force ASN1 encoding to include explicit sequence tags
// Type does not fulfill the BinaryMarshallable interfce and is used only as a
// helper to marshal a NegTokenResp
type gsswrapped struct{ G any }

func (g *gsswrapped) MarshalBinary(meta *encoding.Metadata) ([]byte, error) {
	buf, err := asn1.Marshal(*g)
	if err != nil {
		return nil, err
	}
	if len(buf) == 0 {
		return nil, errors.New("marshaled data is empty")
	}
	buf[0] = 0xa1
	return buf, nil
}

type NegTokenResp struct {
	State         asn1.Enumerated       `asn1:"explicit,optional,omitempty,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,omitempty,tag:1"`
	ResponseToken []byte                `asn1:"explicit,optional,omitempty,tag:2"`
	MechListMIC   []byte                `asn1:"explicit,optional,omitempty,tag:3"`
}

func NewNegTokenResp() (NegTokenResp, error) {
	return NegTokenResp{}, nil
}

func (r *NegTokenResp) MarshalBinary(meta *encoding.Metadata) ([]byte, error) {
	// Oddities in Go's ASN1 package vs SMB encoding mean we have to wrap our
	// struct in another struct to ensure proper tags and lengths are added
	// to encoded data
	wrapped := &gsswrapped{*r}
	return wrapped.MarshalBinary(meta)
}

func (r *NegTokenResp) UnmarshalBinary(buf []byte, meta *encoding.Metadata) (int, error) {
	data := NegTokenResp{}
	rest, err := asn1.UnmarshalWithParams(buf, &data, "explicit,tag:1")
	if err != nil {
		return 0, err
	}
	*r = data
	offset := len(buf) - len(rest)
	return offset, nil
}
