package v1

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/d0rvin/winscope-smb/pkg/protocol"
	"github.com/d0rvin/winscope-smb/pkg/protocol/gss"
	"github.com/d0rvin/winscope-smb/pkg/protocol/ntlmssp"
	"github.com/d0rvin/winscope-smb/pkg/protocol/smb/common"

	"github.com/d0rvin/winscope-smb/pkg/encoding"
)

type Session struct {
	conn *protocol.Connection
}

type Options struct {
	Host        string
	Port        int
	Domain      string
	Workstation string
}

func NewSession(cfg protocol.Config) (s *Session, err error) {
	c, err := protocol.NewConnection(cfg.Host, cfg.Port, cfg.Options...)
	if err != nil {
		return nil, err
	}

	s = &Session{
		conn: c,
	}
	if err := s.conn.Dial("tcp"); err != nil {
		_ = c.Close()
		return nil, err
	}
	return s, nil
}

func (s *Session) Negotiate() error {
	negReq := NewNegotiateReq()
	buf, err := s.send(negReq)
	if err != nil {
		return err
	}

	negRes := NewNegotiateRes()
	if err := encoding.Unmarshal(buf, &negRes); err != nil {
		return err
	}
	if negRes.Status != common.StatusOk {
		return fmt.Errorf("NT status error: %d", negRes.Status)
	}

	if err := common.CheckNTLMSSPSupport(negotiateResAdapter{negRes}); err != nil {
		return err
	}

	return nil
}

func (s *Session) SessionSetupAndX() (*SessionSetupAndXRes, *ntlmssp.Challenge, error) {
	setupReq, err := s.NewSessionSetupAndXReq()
	if err != nil {
		return nil, nil, fmt.Errorf("new session setup and x req err: %v", err)
	}
	buf, err := s.send(setupReq)
	if err != nil {
		return nil, nil, err
	}

	ssres, err := NewSessionSetupAndXRes()
	if err != nil {
		return nil, nil, err
	}
	if err := encoding.Unmarshal(buf, &ssres); err != nil {
		return nil, nil, err
	}

	challenge := ntlmssp.NewChallenge()
	resp := ssres.SecurityBlob
	if err := encoding.Unmarshal(resp.ResponseToken, &challenge); err != nil {
		return nil, nil, err
	}

	if ssres.Status != common.StatusMoreProcessingRequired {
		return nil, nil, fmt.Errorf("NT status error: %s", common.StatusMap[ssres.Status])
	}

	return &ssres, &challenge, nil
}

func (s *Session) Close() error {
	return s.conn.Close()
}

func (s *Session) NewSessionSetupAndXReq() (SessionSetupAndXReq, error) {
	header := newHeader()
	header.Command = CommandSessionSetUpAndX
	header.Flags = FlagsCaseInsensitive | FlagsCanonicalizedPaths
	header.Flags2 = Flags2LongNames | Flags2ExtendedSecurity | Flags2NTStatus
	header.TID = 0xffff
	header.PIDLow = 0xc744

	ntlmsspNeg := ntlmssp.NewNegotiate("", "")
	data, err := encoding.Marshal(ntlmsspNeg)
	if err != nil {
		return SessionSetupAndXReq{}, err
	}

	// Initial session setup request
	init, err := gss.NewNegTokenInit()
	if err != nil {
		return SessionSetupAndXReq{}, err
	}
	init.Data.MechToken = data
	nativeOS := []byte("Unix\x00")
	nativeLanMan := []byte("Samba\x00")
	securityBlobBytes, _ := encoding.Marshal(&init)

	return SessionSetupAndXReq{
		Header:        header,
		WordCount:     0x0c,
		AndXCommand:   0xff,
		MaxBufferSize: 0xf000,
		MaxMpxCount:   0x0002,
		VcNumber:      0x0001,
		Capabilities:  CapUnicode | CapStatus32 | CapLargeReadX | CapLargeWriteX | CapExtendedSecurity,
		ByteCount:     uint16(len(securityBlobBytes) + len(nativeOS) + len(nativeLanMan)),
		SecurityBlob:  &init,
		NativeOS:      nativeOS,
		NativeLanMan:  nativeLanMan,
	}, nil
}

func (s *Session) send(req any) (res []byte, err error) {
	buf, err := encoding.Marshal(req)
	if err != nil {
		return nil, err
	}

	rw := common.NewReadWriter(s.conn)
	if err := common.SendNetBIOSMessage(rw, buf); err != nil {
		return nil, err
	}

	data, err := common.ReceiveNetBIOSMessage(rw)
	if err != nil {
		return nil, err
	}

	protID := data[0:4]
	if !bytes.Contains(protID, []byte(ProtocolSmb)) {
		return nil, errors.New("protocol not implemented")
	}

	return data, nil
}

type negotiateResAdapter struct {
	res NegotiateRes
}

func (a negotiateResAdapter) GetOID() asn1.ObjectIdentifier {
	return a.res.SecurityBlob.OID
}

func (a negotiateResAdapter) GetMechTypes() []asn1.ObjectIdentifier {
	return a.res.SecurityBlob.Data.MechTypes
}
