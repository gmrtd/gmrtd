package cms

import (
	"encoding/asn1"
	"os"
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

func TestSignedMasterListInvalidContent(t *testing.T) {
	root, err := os.ReadFile("testdata/master-list-test-root.cer")
	if err != nil {
		t.Fatal(err)
	}
	// Both lists have a valid CMS signature from a signer with the master-list EKU.
	for _, tc := range []struct {
		name string
		file string
		want string
	}{
		{"malformed list", "malformed-list.cms", "ParseAsn1 error"},
		{"invalid certificate after valid root", "invalid-second-cert.cms", "certPool.Add error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			list, err := os.ReadFile("testdata/" + tc.file)
			if err != nil {
				t.Fatal(err)
			}
			pool, err := CreateCertPoolFromSignedData(list, root)
			if pool != nil || err == nil || !strings.Contains(err.Error(), "[CreateCertPoolFromSignedData] "+tc.want) {
				t.Fatalf("expected nil pool and %q, got pool %v, error %v", tc.want, pool != nil, err)
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

func TestMasterListImportRequiresEverySignerToHaveSigningPurpose(t *testing.T) {
	// OpenSSL signed the same empty master list with two RSA signers under one
	// test root. Only one has the master-list EKU. Leaf serial numbers place
	// the serverAuth-only signer first or last in the DER-ordered SignerInfos.
	root, err := os.ReadFile("testdata/mixed-purpose-root.cer")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ file, index string }{
		{"mixed-purpose-first.cms", "si.Verify(idx:0)"},
		{"mixed-purpose-last.cms", "si.Verify(idx:1)"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			list, err := os.ReadFile("testdata/" + tc.file)
			if err != nil {
				t.Fatal(err)
			}
			pool, err := CreateCertPoolFromSignedData(list, root)
			if pool != nil || err == nil || !strings.Contains(err.Error(), tc.index) || !strings.Contains(err.Error(), "missing master-list signing extended key usage") {
				t.Fatalf("expected nil pool and master-list EKU error at %s, got pool present=%t, err=%v", tc.index, pool != nil, err)
			}
		})
	}
}
