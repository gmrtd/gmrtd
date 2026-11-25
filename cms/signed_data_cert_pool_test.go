package cms

import (
	"encoding/asn1"
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/oid"
)

func TestSignedDataCertPoolErrors(t *testing.T) {
	tests := []struct {
		name string
		list []byte
		root []byte
		want string
	}{
		{"invalid signed data", []byte{0x03, 0x0a}, de_masterListRootCA, "ParseSignedData"},
		{"document security object", fuzzSignedDataBytes, de_masterListRootCA, "expected CSCA master list content type"},
		{"invalid root", de_masterList, []byte{0x03, 0x0a}, "rootCertPool"},
		{"untrusted signer", de_masterList, nl_masterListRootCA, "signedData.Verify"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := CreateCertPoolFromSignedData(tc.list, tc.root)
			if pool != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected no pool and error containing %q, got pool %v, error %v", tc.want, pool != nil, err)
			}
		})
	}
}

func TestMasterListSignerPurpose(t *testing.T) {
	sd, err := ParseSignedData(de_masterList)
	if err != nil {
		t.Fatal(err)
	}
	signers, err := sd.SignerCertificates()
	if err != nil || len(signers) != 1 {
		t.Fatalf("expected one master-list signer, got %d, error %v", len(signers), err)
	}

	var base Extensions
	for _, ext := range signers[0].TbsCertificate.Extensions {
		if !ext.ObjectId.Equal(oid.OidCeExtKeyUsage) {
			base = append(base, ext)
		}
	}
	tests := []struct {
		name     string
		purposes ExtKeyUsage
		wantOK   bool
	}{
		{"absent", nil, false},
		{"any purpose only", ExtKeyUsage{oid.OidAnyExtendedKeyUsage}, false},
		{"unrelated purpose", ExtKeyUsage{{1, 3, 6, 1, 5, 5, 7, 3, 1}}, false},
		{"explicit purpose", ExtKeyUsage{oid.OidCscaMasterListSigningKey}, true},
		{"explicit purpose among others", ExtKeyUsage{oid.OidAnyExtendedKeyUsage, oid.OidCscaMasterListSigningKey}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := signers[0]
			cert.TbsCertificate.Extensions = base
			if tc.purposes != nil {
				der, err := asn1.Marshal(tc.purposes)
				if err != nil {
					t.Fatal(err)
				}
				cert.TbsCertificate.Extensions = append(base, Extension{
					ObjectId: oid.OidCeExtKeyUsage, ExtnValue: asn1.RawValue{Bytes: der},
				})
			}
			err := validateSignerCertExtensions(&cert, sd.Content.EContentType)
			if (err == nil) != tc.wantOK {
				t.Fatalf("expected success %t, got error %v", tc.wantOK, err)
			}
		})
	}
}
