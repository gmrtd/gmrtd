package cms

import (
	"encoding/asn1"
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

// algorithm identifiers and CMSAlgorithmProtection content taken from the ID (Indonesia) RSA-PSS SOD
// sample in passiveauth/passive_auth_test.go
const (
	apDigestSha256Null = "300d06096086480165030402010500"
	apDigestSha384Null = "300d06096086480165030402020500"
	apDigestSha256     = "300b0609608648016503040201"
	apRsaPssOid        = "06092a864886f70d01010a"
	apRsaPssParams     = "3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120"
	apRsaPssParams64   = "3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020140"
	apSha256WithRsaOid = "06092a864886f70d01010b"
	apHmacSha256Oid    = "06082a864886f70d0209"
)

func apDer(tag byte, hexParts ...string) string {
	return utils.BytesToHex(tlv.NewTlvSimpleNode(tlv.TlvTag(tag), utils.HexToBytes(strings.Join(hexParts, ""))).Encode())
}

func apAlgID(t *testing.T, hexStr string) AlgorithmIdentifier {
	t.Helper()
	var ai AlgorithmIdentifier
	if _, err := asn1.Unmarshal(utils.HexToBytes(hexStr), &ai); err != nil {
		t.Fatalf("invalid AlgorithmIdentifier test data: %s", err)
	}
	return ai
}

func apAttr(hexValues string) Attribute {
	return Attribute{Type: oid.OidCmsAlgorithmProtection, Values: asn1.RawValue{Bytes: utils.HexToBytes(hexValues)}}
}

func TestVerifyAlgorithmProtection(t *testing.T) {
	pssSigAlg := apDer(0x30, apRsaPssOid, apRsaPssParams)
	validAttr := apDer(0x30, apDigestSha256Null, apDer(0xa1, apRsaPssOid, apRsaPssParams))

	testCases := []struct {
		name      string
		digestAlg string
		sigAlg    string
		attrs     []Attribute
		expErr    string
	}{
		{name: "absent", attrs: nil},
		{name: "matches (RSA-PSS)", attrs: []Attribute{apAttr(validAttr)}},
		{name: "duplicate attribute", attrs: []Attribute{apAttr(validAttr), apAttr(validAttr)}, expErr: "more than once"},
		{name: "multiple values", attrs: []Attribute{apAttr(validAttr + validAttr)}, expErr: "asn1 parsing error"},
		{name: "malformed", attrs: []Attribute{apAttr(validAttr[:len(validAttr)-4])}, expErr: "asn1 parsing error"},
		{name: "empty", attrs: []Attribute{apAttr("")}, expErr: "asn1 parsing error"},
		{
			name:   "signatureAlgorithm absent",
			attrs:  []Attribute{apAttr(apDer(0x30, apDigestSha256Null))},
			expErr: "must contain signatureAlgorithm",
		},
		{
			name:   "macAlgorithm present",
			attrs:  []Attribute{apAttr(apDer(0x30, apDigestSha256Null, apDer(0xa1, apRsaPssOid, apRsaPssParams), apDer(0xa2, apHmacSha256Oid)))},
			expErr: "must contain signatureAlgorithm",
		},
		{name: "digestAlgorithm substituted", digestAlg: apDigestSha384Null, attrs: []Attribute{apAttr(validAttr)}, expErr: "digestAlgorithm"},
		{name: "digestAlgorithm parameters differ", digestAlg: apDigestSha256, attrs: []Attribute{apAttr(validAttr)}, expErr: "digestAlgorithm"},
		{name: "signatureAlgorithm substituted", sigAlg: apDer(0x30, apSha256WithRsaOid, "0500"), attrs: []Attribute{apAttr(validAttr)}, expErr: "signatureAlgorithm"},
		{name: "signatureAlgorithm parameters differ", sigAlg: apDer(0x30, apRsaPssOid, apRsaPssParams64), attrs: []Attribute{apAttr(validAttr)}, expErr: "signatureAlgorithm"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digestAlg, sigAlg := apDigestSha256Null, pssSigAlg
			if tc.digestAlg != "" {
				digestAlg = tc.digestAlg
			}
			if tc.sigAlg != "" {
				sigAlg = tc.sigAlg
			}
			si := SignerInfo{
				DigestAlgorithm:           apAlgID(t, digestAlg),
				DigestEncryptionAlgorithm: apAlgID(t, sigAlg),
				AuthenticatedAttributes:   tc.attrs,
			}

			err := si.verifyAlgorithmProtection(NewDefaultCMSConfig())

			if tc.expErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.expErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.expErr, err)
			}
		})
	}
}

// The DE master list carries CMSAlgorithmProtection (ECDSA, no parameters), so it exercises the check
// end-to-end, including that a substituted SignerInfo algorithm is caught by it.
func TestVerifyAlgorithmProtectionDeMasterList(t *testing.T) {
	trusted := &GenericCertPool{}
	if err := trusted.Add(de_masterListRootCA); err != nil {
		t.Fatalf("Add error: %s", err)
	}

	parse := func(t *testing.T) *SignedData {
		t.Helper()
		sd, err := ParseSignedData(de_masterList)
		if err != nil {
			t.Fatalf("ParseSignedData error: %s", err)
		}
		if sd.SignerInfos[0].AuthenticatedAttributes.ByOID(oid.OidCmsAlgorithmProtection) == nil {
			t.Fatalf("expected DE master list to carry CMSAlgorithmProtection")
		}
		return sd
	}

	t.Run("valid", func(t *testing.T) {
		if _, err := parse(t).Verify(trusted); err != nil {
			t.Fatalf("Verify error: %s", err)
		}
	})

	t.Run("signatureAlgorithm substituted", func(t *testing.T) {
		sd := parse(t)
		sd.SignerInfos[0].DigestEncryptionAlgorithm = AlgorithmIdentifier{Algorithm: oid.OidEcdsaWithSHA384}

		_, err := sd.Verify(trusted)
		if err == nil || !strings.Contains(err.Error(), "CMSAlgorithmProtection") {
			t.Fatalf("expected CMSAlgorithmProtection error, got: %v", err)
		}
	})
}
