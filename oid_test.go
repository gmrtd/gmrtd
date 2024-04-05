package gmrtd

import "testing"

func TestDecodeAsn1objectId(t *testing.T) {
	oidBytes := HexToBytes("04007F00070202040202")

	expOidStr := "0.4.0.127.0.7.2.2.4.2.2"

	actOidStr := DecodeAsn1objectId(oidBytes)

	if actOidStr != expOidStr {
		t.Errorf("ASN1 OID decode failure (Exp:%s, Act:%s)", expOidStr, actOidStr)
	}
}
