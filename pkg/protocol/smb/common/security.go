package common

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/d0rvin/winscope-smb/pkg/protocol/gss"
)

type SecurityBlob interface {
	GetOID() asn1.ObjectIdentifier
	GetMechTypes() []asn1.ObjectIdentifier
}

func CheckSecurityBlob(blob SecurityBlob) error {
	spnegoOID, err := gss.ObjectIDStrToInt(gss.SpnegoOid)
	if err != nil {
		return err
	}

	oid := blob.GetOID()
	if !oid.Equal(asn1.ObjectIdentifier(spnegoOID)) {
		return fmt.Errorf("unknown security type OID [expecting %s]: %s", gss.SpnegoOid, oid)
	}

	return CheckNTLMSSPSupport(blob)
}

func CheckNTLMSSPSupport(blob SecurityBlob) error {
	ntlmsspOID, err := gss.ObjectIDStrToInt(gss.NtLmSSPMechTypeOid)
	if err != nil {
		return err
	}

	for _, mechType := range blob.GetMechTypes() {
		if mechType.Equal(asn1.ObjectIdentifier(ntlmsspOID)) {
			return nil
		}
	}

	return errors.New("server does not support NTLMSSP")
}
