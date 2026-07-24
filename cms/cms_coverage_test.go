package cms

import (
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

// ---------------------------------------------------------------------------
// Minimal ASN.1 types for building test certificate DER bytes
// ---------------------------------------------------------------------------

type lcAlgID struct {
	Algorithm asn1.ObjectIdentifier
}

type lcValidity struct {
	NotBefore asn1.RawValue
	NotAfter  asn1.RawValue
}

type lcExt struct {
	OID      asn1.ObjectIdentifier
	Critical bool          `asn1:"optional"`
	Value    asn1.RawValue // marshals as OCTET STRING wrapping the inner DER
}

type lcTBS struct {
	Version    int `asn1:"explicit,optional,tag:0"`
	Serial     *big.Int
	SigAlg     lcAlgID
	Issuer     asn1.RawValue
	Validity   lcValidity
	Subject    asn1.RawValue
	SPKI       asn1.RawValue
	Extensions []lcExt `asn1:"explicit,optional,tag:3"`
}

type lcCert struct {
	TBS    lcTBS
	SigAlg lcAlgID
	Sig    asn1.BitString
}

// buildTestCertDER creates minimal DER-encoded certificate bytes that ParseCertificates
// can parse. The cert will have a SubjectKeyIdentifier matching skiBytes plus any
// extraExtensions. If validity is nil, a wide default window is used.
func buildTestCertDER(t *testing.T, skiBytes []byte, extraExtensions []lcExt, validity *lcValidity) []byte {
	t.Helper()

	skiInner, err := asn1.Marshal(skiBytes)
	if err != nil {
		t.Fatalf("marshal SKI bytes: %v", err)
	}

	exts := []lcExt{
		{
			OID:   oid.OidSubjectKeyIdentifier,
			Value: asn1.RawValue{Tag: asn1.TagOctetString, Bytes: skiInner},
		},
	}
	exts = append(exts, extraExtensions...)

	var v lcValidity
	if validity != nil {
		v = *validity
	} else {
		v = lcValidity{
			NotBefore: mustMarshalTime(t, time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)),
			NotAfter:  mustMarshalTime(t, time.Date(2038, 1, 1, 0, 0, 0, 0, time.UTC)),
		}
	}

	cert := lcCert{
		TBS: lcTBS{
			Version:    2,
			Serial:     big.NewInt(42),
			SigAlg:     lcAlgID{Algorithm: oid.OidEcdsaWithSHA256},
			Issuer:     asn1.RawValue{Tag: asn1.TagSequence, Class: asn1.ClassUniversal},
			Validity:   v,
			Subject:    asn1.RawValue{Tag: asn1.TagSequence, Class: asn1.ClassUniversal},
			SPKI:       asn1.RawValue{Tag: asn1.TagSequence, Class: asn1.ClassUniversal},
			Extensions: exts,
		},
		SigAlg: lcAlgID{Algorithm: oid.OidEcdsaWithSHA256},
		Sig:    asn1.BitString{Bytes: []byte{0x00}, BitLength: 8},
	}

	der, err := asn1.Marshal(cert)
	if err != nil {
		t.Fatalf("marshal test cert: %v", err)
	}
	return der
}

// atSODBytes is the AT SOD used across multiple tests in this file.
// DS cert: notBefore=2023-01-31, notAfter=2033-05-06
// SID SKI: e76eaa567acf6568c660c985717c3c8a50bd024b
const atSODHex = "3082064906092a864886f70d010702a082063a30820636020103310f300d06096086480165030402010500308201120606678108010101a0820106048201023081ff020100300d060960864801650304020105003081ea3025020101042090462cd4824bc24ce1ce77e0e40da503b5f25063e61a78e22c3ac04e49b2024330250201020420113888bddfb89a94522959f3cf41007bb1241e2fdfa585d8f480317eb648215f302502010304205c1c4fa5fd3d90662a92d5c6c7ee94030ae7eed9070a6d8f1db376b268d99f83302502010b04202a1704fa33c5b3a5760eb8b48ff0ff9178e6470dc525b79b13bdcbc95d9d83d5302502010c0420c9673800c44a18a3d6e5300e6ad35ab8737dcdfb9f259e43bcff0c9b6a2d78a9302502010e0420aff8c92133072ed5703a84a5a6f5fe148f02a86b36b2d5876193bd48243cd2f2a08203e3308203df30820366a00302010202086189db18b6ede857300a06082a8648ce3d040303303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941301e170d3233303133313038303430325a170d3333303530363038303430325a3054310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d49310f300d060355040513063030343031353119301706035504030c1044532d415553545249412d654d525444308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200048893905193f315ee2e2f1eee3fd5a496f6637deb3778cfe7cc2f6c7f0682acc795b0290265a2cb83119343544f2bbfe42974159ac77b113dafbee860c2523c06a382015930820155301d0603551d0e04160414e76eaa567acf6568c660c985717c3c8a50bd024b301f0603551d230418301680142692c7e398abfbe35192d3f26e9a317d1fed53bd301a0603551d1004133011810f32303233303530363038303430325a30160603551d20040f300d300b06092a28000a0102010101303e0603551d1f043730353033a031a02f862d687474703a2f2f7777772e626d692e67762e61742f637363612f63726c2f43534341415553545249412e63726c300e0603551d0f0101ff04040302078030370603551d120430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f30370603551d110430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f301d06076781080101060204123010020100310b1301501302415213024944300a06082a8648ce3d040303036700306402303af7ae31ca6b8fafca6ec51985997f7119fb2e6d20d61b5327d5740109aa310b410bfb44f354e086f207fcab721e69ae023046c68fb7909f994350a2d1c84d1ae5dff8c00de6d86b7891a6cf90ceea09159402e6e2ed3fa548db28d33146319eefda318201213082011d020101304b303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d4155535452494102086189db18b6ede857300d06096086480165030402010500a066301506092a864886f70d01090331080606678108010101301c06092a864886f70d010905310f170d3233303331373133343031385a302f06092a864886f70d01090431220420eb5dd19b9688751461b3e61c9c80f1e848d91eec210048aca6653279c7c37c76300c06082a8648ce3d04030205000446304402202567959c119ee15d14520eab1b527c2bc493253d6733bbec30295af57e3ceb070220614dcea3ba92499e2212b9cd4159758cd49ae240e74b3e20d8d49183ed1feb09"

// testSKIBytes is an arbitrary SKI used in DS cert extension tests.
var testSKIBytes = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}

// ---------------------------------------------------------------------------
// Option D: zero-coverage functions
// ---------------------------------------------------------------------------

func TestAuthorityKeyIdentifierMarshalJSON(t *testing.T) {
	t.Parallel()

	aki := AuthorityKeyIdentifier{
		KeyIdentifier: []byte{0x01, 0x02, 0x03, 0x04},
	}

	out, err := aki.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected non-empty JSON output")
	}
	if !strings.Contains(string(out), "keyIdentifier") {
		t.Errorf("expected 'keyIdentifier' in JSON, got: %s", out)
	}
}

func TestTBSCertificateSubjectRDN(t *testing.T) {
	t.Parallel()

	pool, err := DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList: %v", err)
	}

	certs := pool.All()
	if len(certs) == 0 {
		t.Fatal("no certs in master list")
	}

	rdn, err := certs[0].TbsCertificate.SubjectRDN()
	if err != nil {
		t.Fatalf("SubjectRDN error: %v", err)
	}
	if rdn == nil {
		t.Fatal("SubjectRDN returned nil")
	}
}

// ---------------------------------------------------------------------------
// Option A: prepareVerificationData error paths
// ---------------------------------------------------------------------------

// buildSimpleSI returns a SignerInfo with the given AttributeList for use in
// prepareVerificationData tests.
func buildSimpleSI(attrs AttributeList) *SignerInfo {
	return &SignerInfo{
		DigestAlgorithm:         AlgorithmIdentifier{Algorithm: oid.OidHashAlgorithmSHA256},
		AuthenticatedAttributes: attrs,
	}
}

func TestPrepareVerificationDataEmpty(t *testing.T) {
	t.Parallel()

	si := buildSimpleSI(nil)
	sd := &SignedData{}
	_, _, _, _, err := si.prepareVerificationData(NewDefaultCMSConfig(), sd)
	if err == nil {
		t.Fatal("expected error for empty authenticated attributes")
	}
	if !strings.Contains(err.Error(), "AuthenticatedAttributes is NOT supported") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrepareVerificationDataMissingContentType(t *testing.T) {
	t.Parallel()

	hashTLV, _ := asn1.Marshal([]byte{0x01, 0x02})
	si := buildSimpleSI(AttributeList{
		{Type: oid.OidMessageDigest, Values: asn1.RawValue{Bytes: hashTLV}},
	})
	sd := &SignedData{}
	_, _, _, _, err := si.prepareVerificationData(NewDefaultCMSConfig(), sd)
	if err == nil {
		t.Fatal("expected error for missing ContentType AA")
	}
	if !strings.Contains(err.Error(), "Expected Authenticated-Attribute") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrepareVerificationDataMissingMessageDigest(t *testing.T) {
	t.Parallel()

	oidTLV, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 3})
	si := buildSimpleSI(AttributeList{
		{Type: oid.OidContentType, Values: asn1.RawValue{Bytes: oidTLV}},
	})
	sd := &SignedData{}
	_, _, _, _, err := si.prepareVerificationData(NewDefaultCMSConfig(), sd)
	if err == nil {
		t.Fatal("expected error for missing MessageDigest AA")
	}
	if !strings.Contains(err.Error(), "Expected Authenticated-Attribute") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrepareVerificationDataOIDDecodeError(t *testing.T) {
	t.Parallel()

	si := buildSimpleSI(AttributeList{
		{Type: oid.OidContentType, Values: asn1.RawValue{Bytes: []byte{0xFF, 0x00}}},
		{Type: oid.OidMessageDigest, Values: asn1.RawValue{Bytes: []byte{0xFF, 0x00}}},
	})
	sd := &SignedData{}
	config := NewDefaultCMSConfig()
	config.Parser = NewErrorParser(errors.New("injected parse error"))

	_, _, _, _, err := si.prepareVerificationData(config, sd)
	if err == nil {
		t.Fatal("expected error from OID decode failure")
	}
	if !strings.Contains(err.Error(), "asn1decodeOid error") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrepareVerificationDataBytesDecodeError(t *testing.T) {
	t.Parallel()

	contentOID := asn1.ObjectIdentifier{1, 2, 3}
	oidTLV, _ := asn1.Marshal(contentOID)

	si := buildSimpleSI(AttributeList{
		{Type: oid.OidContentType, Values: asn1.RawValue{Bytes: oidTLV}},
		{Type: oid.OidMessageDigest, Values: asn1.RawValue{Bytes: []byte{0xFF, 0x00}}},
	})
	sd := &SignedData{}

	callCount := 0
	config := NewDefaultCMSConfig()
	config.Parser = &MockAsn1Parser{
		ParseFunc: func(data []byte, allowExtraData bool, v interface{}) error {
			callCount++
			if callCount == 1 {
				return DefaultAsn1Parser{}.ParseAsn1(data, allowExtraData, v)
			}
			return errors.New("injected bytes decode error")
		},
	}

	_, _, _, _, err := si.prepareVerificationData(config, sd)
	if err == nil {
		t.Fatal("expected error from bytes decode failure")
	}
	if !strings.Contains(err.Error(), "asn1decodeBytes error") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrepareVerificationDataOIDMismatch(t *testing.T) {
	t.Parallel()

	contentOID := asn1.ObjectIdentifier{1, 2, 3}
	differentOID := asn1.ObjectIdentifier{1, 2, 4}
	oidTLV, _ := asn1.Marshal(differentOID) // AA has a different OID than sd.Content.EContentType

	hashBytes := []byte{0x01, 0x02, 0x03}
	hashTLV, _ := asn1.Marshal(hashBytes)

	si := buildSimpleSI(AttributeList{
		{Type: oid.OidContentType, Values: asn1.RawValue{Bytes: oidTLV}},
		{Type: oid.OidMessageDigest, Values: asn1.RawValue{Bytes: hashTLV}},
	})
	sd := &SignedData{Content: EncapContentInfo{EContentType: contentOID}}

	_, _, _, _, err := si.prepareVerificationData(NewDefaultCMSConfig(), sd)
	if err == nil {
		t.Fatal("expected error for Content-Type OID mismatch")
	}
	if !strings.Contains(err.Error(), "differs to Authenticated-Attribute") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrepareVerificationDataHasherError(t *testing.T) {
	t.Parallel()

	contentOID := asn1.ObjectIdentifier{1, 2, 3}
	oidTLV, _ := asn1.Marshal(contentOID)

	someHash := []byte{0xAA, 0xBB}
	hashTLV, _ := asn1.Marshal(someHash)

	si := buildSimpleSI(AttributeList{
		{Type: oid.OidContentType, Values: asn1.RawValue{Bytes: oidTLV}},
		{Type: oid.OidMessageDigest, Values: asn1.RawValue{Bytes: hashTLV}},
	})
	sd := &SignedData{Content: EncapContentInfo{EContentType: contentOID, EContent: []byte("test")}}

	config := NewDefaultCMSConfig()
	config.Hasher = NewErrorHasher(errors.New("injected hasher error"))

	_, _, _, _, err := si.prepareVerificationData(config, sd)
	if err == nil {
		t.Fatal("expected error from CryptoHashByOid failure")
	}
	if !strings.Contains(err.Error(), "CryptoHashByOid error") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrepareVerificationDataHashMismatch(t *testing.T) {
	t.Parallel()

	contentOID := asn1.ObjectIdentifier{1, 2, 3}
	eContent := []byte("test content")

	oidTLV, _ := asn1.Marshal(contentOID)
	wrongHash := make([]byte, 32) // all zeros ≠ sha256("test content")
	wrongHashTLV, _ := asn1.Marshal(wrongHash)

	si := buildSimpleSI(AttributeList{
		{Type: oid.OidContentType, Values: asn1.RawValue{Bytes: oidTLV}},
		{Type: oid.OidMessageDigest, Values: asn1.RawValue{Bytes: wrongHashTLV}},
	})
	sd := &SignedData{Content: EncapContentInfo{EContentType: contentOID, EContent: eContent}}

	_, _, _, _, err := si.prepareVerificationData(NewDefaultCMSConfig(), sd)
	if err == nil {
		t.Fatal("expected error for hash mismatch")
	}
	if !strings.Contains(err.Error(), "Invalid content hash") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SignerInfo.VerifyWithConfig error paths
// ---------------------------------------------------------------------------

func TestSignerInfoVerifyPrepareVerificationDataError(t *testing.T) {
	t.Parallel()

	si := SignerInfo{} // no AuthenticatedAttributes
	sd := &SignedData{}
	config := NewDefaultCMSConfig()
	_, err := si.VerifyWithConfig(config, sd, &GenericCertPool{})
	if err == nil {
		t.Fatal("expected error from prepareVerificationData")
	}
	if !strings.Contains(err.Error(), "prepareVerificationData error") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSignerInfoVerifySigningTimeParseWarn(t *testing.T) {
	// covers the slog.Warn "unable to parse signingTime" branch (line 853)
	sd, err := ParseSignedData(utils.HexToBytes(atSODHex))
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}

	// Replace the SigningTime AA Values with garbage bytes so parsing fails.
	// The Raw field is unchanged so SetOfAsnBytes still builds correct hash input.
	for i, attr := range sd.SignerInfos[0].AuthenticatedAttributes {
		if attr.Type.Equal(oid.OidSigningTime) {
			sd.SignerInfos[0].AuthenticatedAttributes[i].Values = asn1.RawValue{Bytes: []byte{0xFF, 0x00}}
			break
		}
	}

	config := NewDefaultCMSConfig()
	// do NOT set ReferenceTime so the signing-time branch is entered

	// Use empty trusted pool so cert.VerifyWithConfig fails (expected final error).
	_, err = sd.SignerInfos[0].VerifyWithConfig(config, sd, &GenericCertPool{})
	// We expect some error (cert chain verification fails with empty pool).
	// The key coverage is that the signing-time warning branch was reached without panic.
	if err == nil {
		t.Fatal("expected error (empty trusted pool)")
	}
}

func TestSignerInfoVerifyHasherError(t *testing.T) {
	t.Parallel()

	sd, err := ParseSignedData(utils.HexToBytes(atSODHex))
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}

	// First call (in prepareVerificationData for content hash) must return the real
	// sha256 so the hash check passes. Second call (line 861) should fail.
	callCount := 0
	config := NewDefaultCMSConfig()
	config.Hasher = &MockCryptoHasher{
		HashFunc: func(_ asn1.ObjectIdentifier, data []byte) ([]byte, error) {
			callCount++
			if callCount == 1 {
				h := sha256.New()
				h.Write(data)
				return h.Sum(nil), nil
			}
			return nil, errors.New("injected hasher error")
		},
	}
	refTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	config.ReferenceTime = &refTime

	_, err = sd.SignerInfos[0].VerifyWithConfig(config, sd, &GenericCertPool{})
	if err == nil {
		t.Fatal("expected hasher error")
	}
	if !strings.Contains(err.Error(), "[Verify] CryptoHashByOid error") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSignerInfoVerifySelectCertificateError(t *testing.T) {
	t.Parallel()

	sd, err := ParseSignedData(utils.HexToBytes(atSODHex))
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}

	// Replace Certificates.Bytes with garbage to trigger ParseCertificates failure.
	sd.Certificates.Bytes = []byte{0xFF, 0x00}

	config := NewDefaultCMSConfig()
	refTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	config.ReferenceTime = &refTime

	_, err = sd.SignerInfos[0].VerifyWithConfig(config, sd, &GenericCertPool{})
	if err == nil {
		t.Fatal("expected selectCertificate error")
	}
	if !strings.Contains(err.Error(), "selectCertificate error") {
		t.Errorf("unexpected error: %v", err)
	}
}

// buildDSCertTestSIAndSD creates a minimal SignerInfo with SKI-based SID and a SignedData
// containing a test certificate. The AAs are built with the correct content hash so that
// prepareVerificationData passes. The cert has testSKIBytes as its SKI plus extraExtensions.
func buildDSCertTestSIAndSD(t *testing.T, extraExtensions []lcExt, validity *lcValidity) (SignerInfo, *SignedData) {
	t.Helper()

	eContentType := asn1.ObjectIdentifier{1, 2, 3}
	eContent := []byte("test content")
	h := sha256.Sum256(eContent)

	oidTLV, _ := asn1.Marshal(eContentType)
	hashTLV, _ := asn1.Marshal(h[:])

	certDER := buildTestCertDER(t, testSKIBytes, extraExtensions, validity)

	si := SignerInfo{
		DigestAlgorithm:           AlgorithmIdentifier{Algorithm: oid.OidHashAlgorithmSHA256},
		DigestEncryptionAlgorithm: AlgorithmIdentifier{Algorithm: oid.OidEcdsaWithSHA256},
		Sid:                       asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, Bytes: testSKIBytes},
		AuthenticatedAttributes: AttributeList{
			{Type: oid.OidContentType, Values: asn1.RawValue{Bytes: oidTLV}},
			{Type: oid.OidMessageDigest, Values: asn1.RawValue{Bytes: hashTLV}},
		},
		EncryptedDigest: []byte{0x00},
	}

	sd := &SignedData{
		Content: EncapContentInfo{
			EContentType: eContentType,
			EContent:     eContent,
		},
		Certificates: asn1.RawValue{Bytes: certDER},
	}

	return si, sd
}

func TestSignerInfoVerifyDSCertUnrecognizedCritExt(t *testing.T) {
	t.Parallel()

	fakeOid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 50}
	si, sd := buildDSCertTestSIAndSD(t, []lcExt{
		{
			OID:      fakeOid,
			Critical: true,
			Value:    asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte{0x05, 0x00}},
		},
	}, nil)

	config := NewDefaultCMSConfig()
	refTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	config.ReferenceTime = &refTime

	_, err := si.VerifyWithConfig(config, sd, &GenericCertPool{})
	if err == nil {
		t.Fatal("expected error for DS cert with unrecognized critical extension")
	}
	if !strings.Contains(err.Error(), "DS cert has unrecognized critical extension") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSignerInfoVerifyDSCertKUParseError(t *testing.T) {
	t.Parallel()

	// KeyUsage extension with garbage ExtnValue bytes → parse error
	si, sd := buildDSCertTestSIAndSD(t, []lcExt{
		{
			OID:   oid.OidCeKeyUsage,
			Value: asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		},
	}, nil)

	config := NewDefaultCMSConfig()
	refTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	config.ReferenceTime = &refTime

	_, err := si.VerifyWithConfig(config, sd, &GenericCertPool{})
	if err == nil {
		t.Fatal("expected DS cert KeyUsage parse error")
	}
	if !strings.Contains(err.Error(), "DS cert KeyUsage parse error") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSignerInfoVerifyDSCertMissingKU(t *testing.T) {
	t.Parallel()

	// Cert with only SKI (no KeyUsage extension)
	si, sd := buildDSCertTestSIAndSD(t, nil, nil)

	config := NewDefaultCMSConfig()
	refTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	config.ReferenceTime = &refTime

	_, err := si.VerifyWithConfig(config, sd, &GenericCertPool{})
	if err == nil {
		t.Fatal("expected error for DS cert missing keyUsage")
	}
	if !strings.Contains(err.Error(), "DS cert missing keyUsage extension") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSignerInfoVerifyDSCertMissingDigitalSignature(t *testing.T) {
	t.Parallel()

	// KeyUsage present but only keyCertSign (bit 5), no digitalSignature (bit 0).
	// bit 5 in a bit string: byte 0 has bit5 set = 0x04 with 2 unused bits.
	kuBitStr := asn1.BitString{Bytes: []byte{0x04}, BitLength: 6}
	kuInner, _ := asn1.Marshal(kuBitStr) // BIT STRING TLV

	si, sd := buildDSCertTestSIAndSD(t, []lcExt{
		{
			OID:   oid.OidCeKeyUsage,
			Value: asn1.RawValue{Tag: asn1.TagOctetString, Bytes: kuInner},
		},
	}, nil)

	config := NewDefaultCMSConfig()
	refTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	config.ReferenceTime = &refTime

	_, err := si.VerifyWithConfig(config, sd, &GenericCertPool{})
	if err == nil {
		t.Fatal("expected error for DS cert missing digitalSignature")
	}
	if !strings.Contains(err.Error(), "DS cert missing digitalSignature keyUsage") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSignerInfoVerifyDSCertEKUParseError(t *testing.T) {
	t.Parallel()

	// KeyUsage with digitalSignature (bit 0 = 0x80), plus garbage EKU extension.
	kuBitStr := asn1.BitString{Bytes: []byte{0x80}, BitLength: 1}
	kuInner, _ := asn1.Marshal(kuBitStr)

	si, sd := buildDSCertTestSIAndSD(t, []lcExt{
		{
			OID:   oid.OidCeKeyUsage,
			Value: asn1.RawValue{Tag: asn1.TagOctetString, Bytes: kuInner},
		},
		{
			OID:   oid.OidCeExtKeyUsage,
			Value: asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		},
	}, nil)

	config := NewDefaultCMSConfig()
	refTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	config.ReferenceTime = &refTime

	_, err := si.VerifyWithConfig(config, sd, &GenericCertPool{})
	if err == nil {
		t.Fatal("expected DS cert EKU parse error")
	}
	if !strings.Contains(err.Error(), "DS cert ExtKeyUsage parse error") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSignerInfoVerifyDSCertValidityParseError(t *testing.T) {
	t.Parallel()

	// DS cert with digitalSignature KU + invalid validity times.
	kuBitStr := asn1.BitString{Bytes: []byte{0x80}, BitLength: 1}
	kuInner, _ := asn1.Marshal(kuBitStr)

	invalidValidity := &lcValidity{
		NotBefore: asn1.RawValue{Tag: asn1.TagNull},
		NotAfter:  asn1.RawValue{Tag: asn1.TagNull},
	}

	si, sd := buildDSCertTestSIAndSD(t, []lcExt{
		{
			OID:   oid.OidCeKeyUsage,
			Value: asn1.RawValue{Tag: asn1.TagOctetString, Bytes: kuInner},
		},
	}, invalidValidity)

	config := NewDefaultCMSConfig()
	refTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	config.ReferenceTime = &refTime

	_, err := si.VerifyWithConfig(config, sd, &GenericCertPool{})
	if err == nil {
		t.Fatal("expected DS cert validity parse error")
	}
	if !strings.Contains(err.Error(), "DS cert validity parse error") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSignerInfoVerifySignatureError(t *testing.T) {
	t.Parallel()

	sd, err := ParseSignedData(utils.HexToBytes(atSODHex))
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}

	// Replace signature with garbage so VerifySignature fails.
	sd.SignerInfos[0].EncryptedDigest = []byte{0x00, 0x01, 0x02}

	config := NewDefaultCMSConfig()
	// DS cert notBefore=2023-01-31, notAfter=2033-05-06; use a time within that range.
	refTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	config.ReferenceTime = &refTime

	_, err = sd.SignerInfos[0].VerifyWithConfig(config, sd, &GenericCertPool{})
	if err == nil {
		t.Fatal("expected VerifySignature error")
	}
	if !strings.Contains(err.Error(), "VerifySignature error") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Certificate.VerifyWithConfig — cert-level error paths
// ---------------------------------------------------------------------------

func TestCertVerifyValidityParseError(t *testing.T) {
	t.Parallel()

	cert := Certificate{
		TbsCertificate: TBSCertificate{
			Validity: Validity{
				NotBefore: asn1.RawValue{FullBytes: []byte{0x00}}, // invalid
				NotAfter:  asn1.RawValue{FullBytes: []byte{0x00}},
			},
		},
	}
	refTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	config := NewDefaultCMSConfig()
	config.ReferenceTime = &refTime

	_, err := cert.VerifyWithConfig(config, &GenericCertPool{})
	if err == nil {
		t.Fatal("expected cert validity parse error")
	}
	if !strings.Contains(err.Error(), "cert validity parse error") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCertVerifyNotYetValid(t *testing.T) {
	t.Parallel()

	cert := Certificate{
		TbsCertificate: TBSCertificate{
			Validity: Validity{
				NotBefore: mustMarshalTime(t, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
				NotAfter:  mustMarshalTime(t, time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
		},
	}
	refTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	config := NewDefaultCMSConfig()
	config.ReferenceTime = &refTime

	_, err := cert.VerifyWithConfig(config, &GenericCertPool{})
	if err == nil {
		t.Fatal("expected cert not yet valid error")
	}
	if !strings.Contains(err.Error(), "cert not yet valid") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCertVerifyExpired(t *testing.T) {
	t.Parallel()

	cert := Certificate{
		TbsCertificate: TBSCertificate{
			Validity: Validity{
				NotBefore: mustMarshalTime(t, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)),
				NotAfter:  mustMarshalTime(t, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
		},
	}
	refTime := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	config := NewDefaultCMSConfig()
	config.ReferenceTime = &refTime

	_, err := cert.VerifyWithConfig(config, &GenericCertPool{})
	if err == nil {
		t.Fatal("expected cert expired error")
	}
	if !strings.Contains(err.Error(), "cert expired") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCertVerifyAKIParseError(t *testing.T) {
	t.Parallel()

	cert := Certificate{
		TbsCertificate: TBSCertificate{
			Extensions: Extensions{
				{
					ObjectId:  oid.OidAuthorityKeyIdentifier,
					ExtnValue: asn1.RawValue{Bytes: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
				},
			},
		},
	}

	_, err := cert.VerifyWithConfig(NewDefaultCMSConfig(), &GenericCertPool{})
	if err == nil {
		t.Fatal("expected AKI parse error")
	}
	if !strings.Contains(err.Error(), "AuthorityKeyIdentifier error") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCertVerifyUnknownSigAlg(t *testing.T) {
	t.Parallel()

	// Build AKI with a non-nil KeyIdentifier so the AKI check passes.
	akiBytes, _ := asn1.Marshal(AuthorityKeyIdentifier{KeyIdentifier: []byte{0x01}})

	cert := Certificate{
		TbsCertificate: TBSCertificate{
			Extensions: Extensions{
				{
					ObjectId:  oid.OidAuthorityKeyIdentifier,
					ExtnValue: asn1.RawValue{Bytes: akiBytes},
				},
			},
		},
		SignatureAlgorithm: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{9, 9, 9, 9}},
	}

	_, err := cert.VerifyWithConfig(NewDefaultCMSConfig(), &GenericCertPool{})
	if err == nil {
		t.Fatal("expected unable-to-determine-digest-alg error")
	}
	if !strings.Contains(err.Error(), "unable to determine digest-alg") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCertVerifyHasherError(t *testing.T) {
	t.Parallel()

	akiBytes, _ := asn1.Marshal(AuthorityKeyIdentifier{KeyIdentifier: []byte{0x01}})

	cert := Certificate{
		TbsCertificate: TBSCertificate{
			Extensions: Extensions{
				{
					ObjectId:  oid.OidAuthorityKeyIdentifier,
					ExtnValue: asn1.RawValue{Bytes: akiBytes},
				},
			},
		},
		SignatureAlgorithm: AlgorithmIdentifier{Algorithm: oid.OidEcdsaWithSHA256},
	}

	config := NewDefaultCMSConfig()
	config.Hasher = NewErrorHasher(errors.New("injected hasher error"))

	_, err := cert.VerifyWithConfig(config, &GenericCertPool{})
	if err == nil {
		t.Fatal("expected CryptoHashByOid error in cert verify")
	}
	if !strings.Contains(err.Error(), "[Certificate.Verify] CryptoHashByOid error") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Certificate.VerifyWithConfig — parent cert skip branches
// ---------------------------------------------------------------------------

// findCertWithParents locates a cert from the master list that has at least one
// parent in the pool, and returns that cert plus its parents.
func findCertWithParents(t *testing.T) (Certificate, []Certificate) {
	t.Helper()
	pool, err := DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList: %v", err)
	}
	for _, cert := range pool.All() {
		aki, err := cert.TbsCertificate.Extensions.AuthorityKeyIdentifier()
		if err != nil || aki == nil || len(aki.KeyIdentifier) == 0 {
			continue
		}
		parents := pool.BySKI(aki.KeyIdentifier)
		if len(parents) == 0 {
			continue
		}
		return cert, parents
	}
	t.Fatal("no cert with resolvable parent found in master list")
	return Certificate{}, nil
}

func TestCertVerifyParentUnrecognizedCritExt(t *testing.T) {
	t.Parallel()

	target, parents := findCertWithParents(t)
	fakeOid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 51}
	for j := range parents {
		parents[j].TbsCertificate.Extensions = append(parents[j].TbsCertificate.Extensions,
			Extension{
				ObjectId:  fakeOid,
				Critical:  true,
				ExtnValue: asn1.RawValue{Bytes: []byte{0x05, 0x00}},
			},
		)
	}
	pool := &GenericCertPool{}
	pool.AddCerts(parents)

	_, err := target.Verify(pool)
	if err == nil {
		t.Fatal("expected no-valid-CA error when all parents have unrecognized critical ext")
	}
	if !strings.Contains(err.Error(), "no valid CA parent found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCertVerifyParentBCParseError(t *testing.T) {
	t.Parallel()

	target, parents := findCertWithParents(t)
	for j := range parents {
		var filtered Extensions
		for _, ext := range parents[j].TbsCertificate.Extensions {
			if ext.ObjectId.Equal(oid.OidCeBasicConstraints) {
				ext.ExtnValue = asn1.RawValue{Bytes: []byte{0xDE, 0xAD, 0xBE, 0xEF}}
			}
			filtered = append(filtered, ext)
		}
		parents[j].TbsCertificate.Extensions = filtered
	}
	pool := &GenericCertPool{}
	pool.AddCerts(parents)

	_, err := target.Verify(pool)
	if err == nil {
		t.Fatal("expected no-valid-CA error when all parents have malformed BasicConstraints")
	}
	if !strings.Contains(err.Error(), "no valid CA parent found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCertVerifyParentKUParseError(t *testing.T) {
	t.Parallel()

	target, parents := findCertWithParents(t)
	for j := range parents {
		var filtered Extensions
		for _, ext := range parents[j].TbsCertificate.Extensions {
			if ext.ObjectId.Equal(oid.OidCeKeyUsage) {
				ext.ExtnValue = asn1.RawValue{Bytes: []byte{0xDE, 0xAD, 0xBE, 0xEF}}
			}
			filtered = append(filtered, ext)
		}
		parents[j].TbsCertificate.Extensions = filtered
	}
	pool := &GenericCertPool{}
	pool.AddCerts(parents)

	_, err := target.Verify(pool)
	if err == nil {
		t.Fatal("expected no-valid-CA error when all parents have malformed KeyUsage")
	}
	if !strings.Contains(err.Error(), "no valid CA parent found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCertVerifyParentEKUParseError(t *testing.T) {
	t.Parallel()

	target, parents := findCertWithParents(t)
	for j := range parents {
		// Remove any existing EKU and add one with garbage bytes.
		var filtered Extensions
		for _, ext := range parents[j].TbsCertificate.Extensions {
			if !ext.ObjectId.Equal(oid.OidCeExtKeyUsage) {
				filtered = append(filtered, ext)
			}
		}
		filtered = append(filtered, Extension{
			ObjectId:  oid.OidCeExtKeyUsage,
			ExtnValue: asn1.RawValue{Bytes: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		})
		parents[j].TbsCertificate.Extensions = filtered
	}
	pool := &GenericCertPool{}
	pool.AddCerts(parents)

	_, err := target.Verify(pool)
	if err == nil {
		t.Fatal("expected no-valid-CA error when all parents have malformed ExtKeyUsage")
	}
	if !strings.Contains(err.Error(), "no valid CA parent found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCertVerifyParentValidityParseError(t *testing.T) {
	t.Parallel()

	target, parents := findCertWithParents(t)
	for j := range parents {
		parents[j].TbsCertificate.Validity = Validity{
			NotBefore: asn1.RawValue{FullBytes: []byte{0x00}},
			NotAfter:  asn1.RawValue{FullBytes: []byte{0x00}},
		}
	}
	pool := &GenericCertPool{}
	pool.AddCerts(parents)

	refTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	config := NewDefaultCMSConfig()
	config.ReferenceTime = &refTime

	_, err := target.VerifyWithConfig(config, pool)
	if err == nil {
		t.Fatal("expected no-valid-CA error when all parents have invalid validity")
	}
	if !strings.Contains(err.Error(), "no valid CA parent found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCertVerifyParentNotYetValid(t *testing.T) {
	t.Parallel()

	target, parents := findCertWithParents(t)
	// Set all parents to a future validity window so refTime=2025 is before their notBefore.
	for j := range parents {
		parents[j].TbsCertificate.Validity = Validity{
			NotBefore: mustMarshalTime(t, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)),
			NotAfter:  mustMarshalTime(t, time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)),
		}
	}
	pool := &GenericCertPool{}
	pool.AddCerts(parents)

	refTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	config := NewDefaultCMSConfig()
	config.ReferenceTime = &refTime

	_, err := target.VerifyWithConfig(config, pool)
	if err == nil {
		t.Fatal("expected no-valid-CA error when all parents are not yet valid")
	}
	if !strings.Contains(err.Error(), "no valid CA parent found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCertVerifyParentExpired(t *testing.T) {
	t.Parallel()

	target, parents := findCertWithParents(t)
	// Set all parents to an old validity window so refTime=2025 is after their notAfter.
	for j := range parents {
		parents[j].TbsCertificate.Validity = Validity{
			NotBefore: mustMarshalTime(t, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)),
			NotAfter:  mustMarshalTime(t, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)),
		}
	}
	pool := &GenericCertPool{}
	pool.AddCerts(parents)

	refTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	config := NewDefaultCMSConfig()
	config.ReferenceTime = &refTime

	_, err := target.VerifyWithConfig(config, pool)
	if err == nil {
		t.Fatal("expected no-valid-CA error when all parents are expired")
	}
	if !strings.Contains(err.Error(), "no valid CA parent found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// selectCertificate - JMRTD-style fallback (issue #440)
// ---------------------------------------------------------------------------

// When the SignerIdentifier matches no embedded certificate but the SOD embeds
// exactly one certificate, selectCertificate falls back to that sole cert
// (matching JMRTD, which never selects by SID). Trust is still gated downstream
// by the signature and CSCA-chain checks.
func TestSelectCertificateFallbackSingleEmbeddedCert(t *testing.T) {
	t.Parallel()

	certDER := buildTestCertDER(t, testSKIBytes, nil, nil)
	sd := &SignedData{Certificates: asn1.RawValue{Bytes: certDER}}

	// SKI-based SID whose bytes match no embedded cert.
	si := SignerInfo{Sid: asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, Bytes: []byte{0xde, 0xad, 0xbe, 0xef}}}

	cert, err := si.selectCertificate(sd)
	if err != nil {
		t.Fatalf("expected fallback to succeed, got error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected the sole embedded cert, got nil")
	}
	if cert.TbsCertificate.SerialNumber.Cmp(big.NewInt(42)) != 0 {
		t.Errorf("unexpected cert selected (serial %v)", cert.TbsCertificate.SerialNumber)
	}
}

// When the SID matches nothing and MORE than one certificate is embedded, the
// choice is ambiguous, so selectCertificate must NOT fall back - it errors.
func TestSelectCertificateNoFallbackMultipleEmbeddedCerts(t *testing.T) {
	t.Parallel()

	cert1 := buildTestCertDER(t, testSKIBytes, nil, nil)
	ski2 := []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34}
	cert2 := buildTestCertDER(t, ski2, nil, nil)

	both := append(append([]byte{}, cert1...), cert2...)
	sd := &SignedData{Certificates: asn1.RawValue{Bytes: both}}

	si := SignerInfo{Sid: asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, Bytes: []byte{0xde, 0xad, 0xbe, 0xef}}}

	_, err := si.selectCertificate(sd)
	if err == nil {
		t.Fatal("expected error when SID matches nothing and multiple certs are embedded")
	}
	if !strings.Contains(err.Error(), "got:") {
		t.Errorf("unexpected error: %v", err)
	}
}

// With no embedded certificates at all there is nothing to fall back to.
func TestSelectCertificateNoFallbackWhenNoCerts(t *testing.T) {
	t.Parallel()

	sd := &SignedData{}
	si := SignerInfo{Sid: asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, Bytes: []byte{0xde, 0xad, 0xbe, 0xef}}}

	_, err := si.selectCertificate(sd)
	if err == nil {
		t.Fatal("expected error when no certs are embedded")
	}
	if !strings.Contains(err.Error(), "got:0") {
		t.Errorf("unexpected error: %v", err)
	}
}
