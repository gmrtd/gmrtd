package cms

import (
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/oid"
)

// ---------------------------------------------------------------------------
// ParseSignedData – error paths
// ---------------------------------------------------------------------------

func TestParseSignedDataMalformedContentInfo(t *testing.T) {
	t.Parallel()

	_, err := ParseSignedData([]byte{0xff, 0x00})
	if err == nil {
		t.Fatal("expected error for malformed ContentInfo bytes")
	}
	if !strings.Contains(err.Error(), "[ParseSignedData]") {
		t.Errorf("unexpected error text: %v", err)
	}
}

func TestParseSignedDataWrongOID(t *testing.T) {
	t.Parallel()

	// Manually constructed ContentInfo carrying id-data (1.2.840.113549.1.7.1)
	// instead of id-signedData.  The inner [0] EXPLICIT wraps a NULL value so
	// the outer ContentInfo parses cleanly; only the OID check should fail.
	//
	//  SEQUENCE {
	//    OID 1.2.840.113549.1.7.1   (id-data)
	//    [0] EXPLICIT { NULL }
	//  }
	data := []byte{
		0x30, 0x0f,
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, // id-data OID
		0xa0, 0x02, 0x05, 0x00, // [0] EXPLICIT { NULL }
	}

	_, err := ParseSignedData(data)
	if err == nil {
		t.Fatal("expected error for wrong OID")
	}
	if !strings.Contains(err.Error(), "invalid OID") {
		t.Errorf("unexpected error text: %v", err)
	}
}

func TestParseSignedDataMalformedInnerContent(t *testing.T) {
	t.Parallel()

	// Manually constructed ContentInfo with correct id-signedData OID but with
	// a NULL as the inner value.  The outer ContentInfo and OID are valid; only
	// the attempt to parse the inner bytes as a SignedData SEQUENCE should fail.
	//
	//  SEQUENCE {
	//    OID 1.2.840.113549.1.7.2   (id-signedData)
	//    [0] EXPLICIT { NULL }
	//  }
	data := []byte{
		0x30, 0x0f,
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, // id-signedData OID
		0xa0, 0x02, 0x05, 0x00, // [0] EXPLICIT { NULL }
	}

	_, err := ParseSignedData(data)
	if err == nil {
		t.Fatal("expected error for malformed inner SignedData")
	}
	if !strings.Contains(err.Error(), "asn1 parsing error (signedData)") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ParseCertificates – edge cases
// ---------------------------------------------------------------------------

func TestParseCertificatesEmptyInput(t *testing.T) {
	t.Parallel()

	certs, err := ParseCertificates([]byte{})
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs, got %d", len(certs))
	}
}

func TestParseCertificatesMalformed(t *testing.T) {
	t.Parallel()

	_, err := ParseCertificates([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	if err == nil {
		t.Fatal("expected error for malformed certificate bytes")
	}
	if !strings.Contains(err.Error(), "[ParseCertificates]") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ParseECSpecifiedDomain – error paths
// ---------------------------------------------------------------------------

func TestParseECSpecifiedDomainWrongOID(t *testing.T) {
	t.Parallel()

	algId := AlgorithmIdentifier{
		Algorithm: oid.OidRsaEncryption, // not id-ecPublicKey
	}
	_, err := ParseECSpecifiedDomain(&algId)
	if err == nil {
		t.Fatal("expected error for non-EC-public-key OID")
	}
	if !strings.Contains(err.Error(), "expected ecPublicKey OID") {
		t.Errorf("unexpected error text: %v", err)
	}
}

func TestParseECSpecifiedDomainNonPrimeField(t *testing.T) {
	t.Parallel()

	// Build a minimal ECSpecifiedDomain DER structure where fieldType is
	// characteristicTwoField (1.2.840.10045.1.2) instead of primeField.
	type testField struct {
		FieldType  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}
	type testCurve struct {
		A []byte
		B []byte
	}
	type testDomain struct {
		Version  int
		FieldId  testField
		Curve    testCurve
		Base     []byte
		Order    *big.Int
		Cofactor *big.Int
	}

	domBytes, err := asn1.Marshal(testDomain{
		Version: 1,
		FieldId: testField{
			FieldType:  asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 2}, // characteristicTwoField
			Parameters: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagInteger, Bytes: []byte{0x01}},
		},
		Curve:    testCurve{A: []byte{0x01}, B: []byte{0x01}},
		Base:     []byte{0x04, 0x01, 0x01},
		Order:    big.NewInt(7),
		Cofactor: big.NewInt(1),
	})
	if err != nil {
		t.Fatalf("test setup: marshal error: %v", err)
	}

	algId := AlgorithmIdentifier{
		Algorithm:  oid.OidEcPublicKey,
		Parameters: asn1.RawValue{FullBytes: domBytes},
	}
	_, err = ParseECSpecifiedDomain(&algId)
	if err == nil {
		t.Fatal("expected error for non-prime field")
	}
	if !strings.Contains(err.Error(), "PrimeField OID expected") {
		t.Errorf("unexpected error text: %v", err)
	}
}

func TestParseECSpecifiedDomainMalformedParameters(t *testing.T) {
	t.Parallel()

	algId := AlgorithmIdentifier{
		Algorithm:  oid.OidEcPublicKey,
		Parameters: asn1.RawValue{FullBytes: []byte{0xaa, 0xbb, 0xcc}}, // unparseable garbage
	}
	_, err := ParseECSpecifiedDomain(&algId)
	if err == nil {
		t.Fatal("expected error for malformed EC parameters")
	}
	if !strings.Contains(err.Error(), "ASN1 parsing error") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Certificate.VerifyWithConfig – untested error branches
// ---------------------------------------------------------------------------

func TestCertificateVerifyMissingAKI(t *testing.T) {
	t.Parallel()

	// A cert with no extensions has no AKI, so Verify must return an error
	// before it attempts any digest or signature operations.
	cert := Certificate{
		TbsCertificate: TBSCertificate{
			Extensions: Extensions{},
		},
	}
	_, err := cert.Verify(&GenericCertPool{})
	if err == nil {
		t.Fatal("expected error for cert missing AKI")
	}
	if !strings.Contains(err.Error(), "AKI missing from cert") {
		t.Errorf("unexpected error text: %v", err)
	}
}

func TestCertificateVerifyParentNotFound(t *testing.T) {
	t.Parallel()

	certPool, err := DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList error: %v", err)
	}

	// Find any cert that has an AKI (i.e. is not self-signed).
	var targetCert Certificate
	var found bool
	for _, cert := range certPool.All() {
		aki, err := cert.TbsCertificate.Extensions.AuthorityKeyIdentifier()
		if err != nil || aki == nil || len(aki.KeyIdentifier) == 0 {
			continue
		}
		targetCert = cert
		found = true
		break
	}
	if !found {
		t.Fatal("no non-self-signed cert found in master list")
	}

	// Passing an empty pool means BySKI will return nothing → "unable to locate parent"
	_, err = targetCert.Verify(&GenericCertPool{})
	if err == nil {
		t.Fatal("expected error when no parent cert is available")
	}
	if !strings.Contains(err.Error(), "unable to locate parent certificate") {
		t.Errorf("unexpected error text: %v", err)
	}
}

func TestCertificateVerifySignatureNotVerified(t *testing.T) {
	t.Parallel()

	certPool, err := DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList error: %v", err)
	}

	// Find a cert whose parent is present in the pool so that BySKI succeeds,
	// then tamper with the signature so that verification fails.
	var targetCert Certificate
	var parentPool *GenericCertPool
	for _, cert := range certPool.All() {
		aki, err := cert.TbsCertificate.Extensions.AuthorityKeyIdentifier()
		if err != nil || aki == nil || len(aki.KeyIdentifier) == 0 {
			continue
		}
		parents := certPool.BySKI(aki.KeyIdentifier)
		if len(parents) == 0 {
			continue
		}
		targetCert = cert
		parentPool = &GenericCertPool{}
		parentPool.AddCerts(parents)
		break
	}
	if parentPool == nil {
		t.Fatal("no suitable cert with a resolvable parent found in master list")
	}

	// Flip the first byte of the signature so every parent-cert verification fails.
	tamperedSig := make([]byte, len(targetCert.SignatureValue.Bytes))
	copy(tamperedSig, targetCert.SignatureValue.Bytes)
	tamperedSig[0] ^= 0xff
	targetCert.SignatureValue.Bytes = tamperedSig

	_, err = targetCert.Verify(parentPool)
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
	if !strings.Contains(err.Error(), "signature not verified against matched certificates") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DefaultAsn1Parser – trailing-data error
// ---------------------------------------------------------------------------

func TestDefaultAsn1ParserTrailingData(t *testing.T) {
	t.Parallel()

	// Valid ASN.1 NULL followed by an extra zero byte.
	data := []byte{0x05, 0x00, 0x00}
	var val asn1.RawValue

	err := DefaultAsn1Parser{}.ParseAsn1(data, false, &val)
	if err == nil {
		t.Fatal("expected error for trailing data")
	}
	if !strings.Contains(err.Error(), "unexpected data remaining") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// ---------------------------------------------------------------------------
// AttributeList.ByOID – not-found path
// ---------------------------------------------------------------------------

func TestAttributeListByOIDNotFound(t *testing.T) {
	t.Parallel()

	attrs := AttributeList{
		{Type: asn1.ObjectIdentifier{1, 2, 3}},
	}

	result := attrs.ByOID(asn1.ObjectIdentifier{9, 9, 9})
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// ParseRDNSequence – error path
// ---------------------------------------------------------------------------

func TestParseRDNSequenceError(t *testing.T) {
	t.Parallel()

	_, err := ParseRDNSequence([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	if err == nil {
		t.Fatal("expected error for malformed RDN bytes")
	}
	if !strings.Contains(err.Error(), "[ParseRDNSequence]") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RDNSequence.ByOID – no-match path
// ---------------------------------------------------------------------------

func TestRDNSequenceByOIDNotFound(t *testing.T) {
	t.Parallel()

	rdn := RDNSequence{}

	result := rdn.ByOID(asn1.ObjectIdentifier{9, 9, 9})
	if len(result) != 0 {
		t.Fatalf("expected empty bytes, got %x", result)
	}
}

// ---------------------------------------------------------------------------
// Extensions.AuthorityKeyIdentifier – parse error
// ---------------------------------------------------------------------------

func TestExtensionsAuthorityKeyIdentifierParseError(t *testing.T) {
	t.Parallel()

	extensions := Extensions{
		{
			ObjectId:  oid.OidAuthorityKeyIdentifier,
			ExtnValue: asn1.RawValue{Bytes: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		},
	}

	_, err := extensions.AuthorityKeyIdentifier()
	if err == nil {
		t.Fatal("expected error for malformed AKI bytes")
	}
	if !strings.Contains(err.Error(), "[AuthorityKeyIdentifier]") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Extensions.SubjectKeyIdentifier – not-found (nil return) and parse error
// ---------------------------------------------------------------------------

func TestExtensionsSubjectKeyIdentifierNotFound(t *testing.T) {
	t.Parallel()

	// Extensions list has no SKI entry.
	extensions := Extensions{
		{ObjectId: oid.OidAuthorityKeyIdentifier},
	}

	ski, err := extensions.SubjectKeyIdentifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ski != nil {
		t.Fatalf("expected nil SKI, got %v", ski)
	}
}

func TestExtensionsSubjectKeyIdentifierParseError(t *testing.T) {
	t.Parallel()

	extensions := Extensions{
		{
			ObjectId:  oid.OidSubjectKeyIdentifier,
			ExtnValue: asn1.RawValue{Bytes: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		},
	}

	_, err := extensions.SubjectKeyIdentifier()
	if err == nil {
		t.Fatal("expected error for malformed SKI bytes")
	}
	if !strings.Contains(err.Error(), "[SubjectKeyIdentifier]") {
		t.Errorf("unexpected error text: %v", err)
	}
}
