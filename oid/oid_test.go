package oid

import (
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestDecodeAsn1objectId(t *testing.T) {
	oidBytes := utils.HexToBytes("04007F00070202040202")

	expOidStr := "0.4.0.127.0.7.2.2.4.2.2"

	actOid := DecodeAsn1objectId(oidBytes)

	if actOid.String() != expOidStr {
		t.Errorf("ASN1 OID decode failure (Exp:%s, Act:%s)", expOidStr, actOid.String())
	}
}
