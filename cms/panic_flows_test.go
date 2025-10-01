package cms

import (
	"encoding/asn1"
	"testing"

	"github.com/gmrtd/gmrtd/oid"
)

// TestGetAuthorityKeyIdentifierWithInvalidData tests panic recovery
// for GetAuthorityKeyIdentifier with invalid extension data (cms.go:297)
func TestGetAuthorityKeyIdentifierWithInvalidData(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Recovered from panic as expected: %v", r)
		}
	}()

	// Create extensions with invalid AuthorityKeyIdentifier data
	invalidExtnValue := asn1.RawValue{
		Bytes: []byte{0xFF, 0xFF, 0xFF}, // Invalid ASN.1 data
	}

	extensions := Extensions{
		{
			ObjectId:  oid.OidAuthorityKeyIdentifier,
			ExtnValue: invalidExtnValue,
		},
	}

	// This should panic due to invalid ASN.1 parsing
	_ = extensions.GetAuthorityKeyIdentifier()

	// If we get here without panic, the test should fail
	t.Fatal("expected panic but didn't get one")
}

// TestGetSubjectKeyIdentifierWithInvalidData tests panic recovery
// for GetSubjectKeyIdentifier with invalid extension data (cms.go:314)
func TestGetSubjectKeyIdentifierWithInvalidData(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Recovered from panic as expected: %v", r)
		}
	}()

	// Create extensions with invalid SubjectKeyIdentifier data
	invalidExtnValue := asn1.RawValue{
		Bytes: []byte{0xFF, 0xFF, 0xFF}, // Invalid ASN.1 data
	}

	extensions := Extensions{
		{
			ObjectId:  oid.OidSubjectKeyIdentifier,
			ExtnValue: invalidExtnValue,
		},
	}

	// This should panic due to invalid ASN.1 parsing
	_ = extensions.GetSubjectKeyIdentifier()

	// If we get here without panic, the test should fail
	t.Fatal("expected panic but didn't get one")
}

// TestGetCRLNumberWithInvalidData tests panic recovery for GetCRLNumber
// with invalid extension data (cms.go:330)
func TestGetCRLNumberWithInvalidData(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Recovered from panic as expected: %v", r)
		}
	}()

	// Create extensions with invalid CRL number data
	invalidExtnValue := asn1.RawValue{
		Bytes: []byte{0xFF, 0xFF, 0xFF}, // Invalid ASN.1 data
	}

	extensions := Extensions{
		{
			ObjectId:  oid.OidCeCRLNumber,
			ExtnValue: invalidExtnValue,
		},
	}

	// This should panic due to invalid ASN.1 parsing
	_ = extensions.GetCRLNumber()

	// If we get here without panic, the test should fail
	t.Fatal("expected panic but didn't get one")
}

// TestGetCRLNumberWithWrongTag tests panic for CRL number with wrong ASN.1 tag (cms.go:334)
func TestGetCRLNumberWithWrongTag(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Recovered from panic as expected: %v", r)
		}
	}()

	// Create a valid ASN.1 value but with wrong tag (not INTEGER)
	// Tag 4 is OCTET STRING instead of INTEGER (tag 2)
	wrongTagData, _ := asn1.Marshal([]byte{0x01, 0x02, 0x03})

	extnValue := asn1.RawValue{
		Bytes: wrongTagData,
	}

	extensions := Extensions{
		{
			ObjectId:  oid.OidCeCRLNumber,
			ExtnValue: extnValue,
		},
	}

	// This should panic due to unexpected tag
	_ = extensions.GetCRLNumber()

	// If we get here without panic, the test should fail
	t.Fatal("expected panic but didn't get one")
}

// TestParseRDNSequenceWithInvalidData tests panic for ParseRDNSequence
// with invalid data (cms.go:355)
func TestParseRDNSequenceWithInvalidData(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Recovered from panic as expected: %v", r)
		}
	}()

	// Invalid ASN.1 data
	invalidData := []byte{0xFF, 0xFF, 0xFF}

	// This should panic due to invalid ASN.1 parsing
	_ = ParseRDNSequence(invalidData)

	// If we get here without panic, the test should fail
	t.Fatal("expected panic but didn't get one")
}

// TestAsn1decodeOidWithInvalidData tests panic for asn1decodeOid
// with invalid data (cms.go:711)
func TestAsn1decodeOidWithInvalidData(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Recovered from panic as expected: %v", r)
		}
	}()

	// Invalid ASN.1 data for OID
	invalidData := []byte{0xFF, 0xFF, 0xFF}

	// This should panic due to invalid ASN.1 parsing
	_ = asn1decodeOid(invalidData)

	// If we get here without panic, the test should fail
	t.Fatal("expected panic but didn't get one")
}

// TestAsn1decodeBytesWithInvalidData tests panic for asn1decodeBytes
// with invalid data (cms.go:720)
func TestAsn1decodeBytesWithInvalidData(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Recovered from panic as expected: %v", r)
		}
	}()

	// Invalid ASN.1 data for bytes
	invalidData := []byte{0xFF, 0xFF, 0xFF}

	// This should panic due to invalid ASN.1 parsing
	_ = asn1decodeBytes(invalidData)

	// If we get here without panic, the test should fail
	t.Fatal("expected panic but didn't get one")
}

// TestAsn1decodeSubjectPublicKeyInfoWithInvalidData tests panic for
// Asn1decodeSubjectPublicKeyInfo with invalid data (cms.go:729)
func TestAsn1decodeSubjectPublicKeyInfoWithInvalidData(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Recovered from panic as expected: %v", r)
		}
	}()

	// Invalid ASN.1 data for SubjectPublicKeyInfo
	invalidData := []byte{0xFF, 0xFF, 0xFF}

	// This should panic due to invalid ASN.1 parsing
	_ = Asn1decodeSubjectPublicKeyInfo(invalidData)

	// If we get here without panic, the test should fail
	t.Fatal("expected panic but didn't get one")
}

// TestGetRsaPubKeyWithWrongAlgorithm tests panic for GetRsaPubKey
// when algorithm doesn't match RSA (cms.go:816)
func TestGetRsaPubKeyWithWrongAlgorithm(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Recovered from panic as expected: %v", r)
		}
	}()

	// Create a SubjectPublicKeyInfo with EC algorithm instead of RSA
	spki := SubjectPublicKeyInfo{
		Algorithm: AlgorithmIdentifier{
			Algorithm: oid.OidEcPublicKey, // Wrong! Should be RSA
		},
		SubjectPublicKey: asn1.BitString{
			Bytes: []byte{0x01, 0x02, 0x03},
		},
	}

	// This should panic due to algorithm mismatch
	_ = spki.GetRsaPubKey()

	// If we get here without panic, the test should fail
	t.Fatal("expected panic but didn't get one")
}

// TestGetRsaPubKeyWithInvalidPublicKeyData tests panic for GetRsaPubKey
// when public key data is invalid (cms.go:822)
func TestGetRsaPubKeyWithInvalidPublicKeyData(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Recovered from panic as expected: %v", r)
		}
	}()

	// Create a SubjectPublicKeyInfo with correct algorithm but invalid key data
	spki := SubjectPublicKeyInfo{
		Algorithm: AlgorithmIdentifier{
			Algorithm: oid.OidRsaEncryption,
		},
		SubjectPublicKey: asn1.BitString{
			Bytes: []byte{0xFF, 0xFF, 0xFF}, // Invalid RSA key data
		},
	}

	// This should panic due to invalid ASN.1 parsing of RSA key
	_ = spki.GetRsaPubKey()

	// If we get here without panic, the test should fail
	t.Fatal("expected panic but didn't get one")
}

// TestExtensionsGettersWithValidData ensures normal flow works without panics
func TestExtensionsGettersWithValidData(t *testing.T) {
	// Get a real certificate from the German master list
	germanCertPool, err := GetGermanMasterList()
	if err != nil {
		t.Fatalf("GetGermanMasterList error: %v", err)
	}

	allCerts := germanCertPool.GetAll()
	if len(allCerts) == 0 {
		t.Skip("No certificates available for testing")
	}

	testCert := &allCerts[0]

	// Test GetAuthorityKeyIdentifier (should not panic)
	aki := testCert.TbsCertificate.Extensions.GetAuthorityKeyIdentifier()
	t.Logf("AKI: %v", aki)

	// Test GetSubjectKeyIdentifier (should not panic)
	ski := testCert.TbsCertificate.Extensions.GetSubjectKeyIdentifier()
	if ski != nil {
		t.Logf("SKI: %x", *ski)
	}

	// Test ParseRDNSequence (should not panic)
	rdn := testCert.TbsCertificate.GetIssuerRDN()
	country := rdn.GetByOID(oid.OidCountryName)
	t.Logf("Issuer country: %s", string(country))

	// Parse a CRL and test GetCRLNumber
	crl, err := ParseCertificateRevocationList(de_clr)
	if err != nil {
		t.Fatalf("ParseCertificateRevocationList error: %v", err)
	}

	crlNumber := crl.TBSCertList.Extensions.GetCRLNumber()
	if crlNumber != nil {
		t.Logf("CRL Number: %s", crlNumber.String())
	}

	t.Log("All extensions getters worked without panics")
}
