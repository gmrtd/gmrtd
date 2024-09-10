package oid

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestOidHasPrefix(t *testing.T) {
	testCases := []struct {
		oid       asn1.ObjectIdentifier
		prefixOid asn1.ObjectIdentifier
		hasPrefix bool
	}{
		{
			// FALSE: oid matches prefixOid
			oid:       asn1.ObjectIdentifier{1, 2, 3, 4},
			prefixOid: asn1.ObjectIdentifier{1, 2, 3, 4},
			hasPrefix: false,
		},
		{
			// FALSE: oid shorter than prefixOid
			oid:       asn1.ObjectIdentifier{1, 2, 3},
			prefixOid: asn1.ObjectIdentifier{1, 2, 3, 4},
			hasPrefix: false,
		},
		{
			// TRUE: oid longer than prefixOid
			oid:       asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			prefixOid: asn1.ObjectIdentifier{1, 2, 3, 4},
			hasPrefix: true,
		},
	}
	for _, tc := range testCases {
		hasPrefix := OidHasPrefix(tc.oid, tc.prefixOid)

		if hasPrefix != tc.hasPrefix {
			t.Errorf("OidHasPrefix result differs to expected (exp:%t, act:%t)", tc.hasPrefix, hasPrefix)
		}
	}
}

func TestOidBytes(t *testing.T) {
	var oid asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 2, 3, 4}

	var expBytes []byte = utils.HexToBytes("2a0304")

	actBytes := OidBytes(oid)

	if !bytes.Equal(expBytes, actBytes) {
		t.Errorf("OID bytes differ to expected (exp:%x, act:%x)", expBytes, actBytes)
	}
}

func TestOidBytesErr(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	var badOid asn1.ObjectIdentifier = nil

	tmpBytes := OidBytes(badOid)

	if len(tmpBytes) > 0 {
		t.Errorf("didn't expect any data for error case")
	}

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestDecodeAsn1objectId(t *testing.T) {
	oidBytes := utils.HexToBytes("04007F00070202040202")

	expOidStr := "0.4.0.127.0.7.2.2.4.2.2"

	actOid := DecodeAsn1objectId(oidBytes)

	if actOid.String() != expOidStr {
		t.Errorf("ASN1 OID decode failure (Exp:%s, Act:%s)", expOidStr, actOid.String())
	}
}

func TestDecodeAsn1objectIdErr(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	oidBytes := []byte{}

	actOid := DecodeAsn1objectId(oidBytes)

	if len(actOid) > 0 {
		t.Errorf("didn't expect any data for error case")
	}

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}
