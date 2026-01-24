package v2

import (
	"bufio"
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
	conn      *protocol.Connection
	rw        *bufio.ReadWriter
	messageID uint64
	sessionID uint64
}

func NewSession(cfg protocol.Config) (s *Session, err error) {
	c, err := protocol.NewConnection(cfg.Host, cfg.Port, cfg.Options...)
	if err != nil {
		return nil, err
	}

	s = &Session{
		conn: c,
		rw:   bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c)),
	}
	if err := s.conn.Dial("tcp"); err != nil {
		_ = c.Close()
		return nil, err
	}
	return s, nil
}

func (s *Session) Negotiate() error {
	negReq := NewNegotiateReq(s.messageID)
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

func (s *Session) Close() error {
	return s.conn.Close()
}

func (s *Session) Setup1() (*ntlmssp.Challenge, error) {
	ssreq, err := s.NewSessionSetup1Req()
	if err != nil {
		return nil, err
	}

	buf, err := s.send(ssreq)
	if err != nil {
		return nil, err
	}

	ssRes, err := NewSessionSetup1Res()
	if err != nil {
		return nil, err
	}
	if err := encoding.Unmarshal(buf, &ssRes); err != nil {
		return nil, err
	}

	challenge := ntlmssp.NewChallenge()
	resp := ssRes.SecurityBlob
	if err := encoding.Unmarshal(resp.ResponseToken, &challenge); err != nil {
		return nil, err
	}

	if ssRes.Status != common.StatusMoreProcessingRequired {
		return nil, fmt.Errorf("NT status error: %s", common.StatusMap[ssRes.Status])
	}

	return &challenge, nil
}

func (s *Session) NewSessionSetup1Req() (SessionSetup1Req, error) {
	header := newHeader()
	header.Command = CommandSessionSetup
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID

	ntlmsspNeg := ntlmssp.NewNegotiate("", "")
	data, err := encoding.Marshal(ntlmsspNeg)
	if err != nil {
		return SessionSetup1Req{}, err
	}

	if s.sessionID != 0 {
		return SessionSetup1Req{}, errors.New("bad session ID for session setup 1 message")
	}

	// Initial session setup request
	init, err := gss.NewNegTokenInit()
	if err != nil {
		return SessionSetup1Req{}, err
	}
	init.Data.MechToken = data

	return SessionSetup1Req{
		Header:               header,
		StructureSize:        25,
		SecurityMode:         byte(SecurityModeSigningEnabled),
		SecurityBufferOffset: 88,
		SecurityBlob:         &init,
	}, nil
}

func (s *Session) send(req any) (res []byte, err error) {
	buf, err := encoding.Marshal(req)
	if err != nil {
		return nil, err
	}

	if err := common.SendNetBIOSMessage(s.rw, buf); err != nil {
		return nil, err
	}

	data, err := common.ReceiveNetBIOSMessage(s.rw)
	if err != nil {
		return nil, err
	}

	protID := data[0:4]
	switch string(protID) {
	default:
		return nil, errors.New("protocol not implemented")
	case ProtocolSmb2:
		s.messageID++
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
