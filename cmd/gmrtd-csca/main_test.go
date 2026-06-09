package main

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/iso3166"
	"github.com/gmrtd/gmrtd/oid"
)

// buildSKIExt constructs an SKI X.509 extension with the given key identifier.
func buildSKIExt(ski []byte) cms.Extension {
	encoded, _ := asn1.Marshal(ski)
	return cms.Extension{
		ObjectId:  oid.OidSubjectKeyIdentifier,
		ExtnValue: asn1.RawValue{Bytes: encoded},
	}
}

// buildAKIExt constructs an AKI X.509 extension with the given key identifier.
func buildAKIExt(keyId []byte) cms.Extension {
	type tempAKI struct {
		KeyIdentifier []byte `asn1:"optional,implicit,tag:0"`
	}
	encoded, _ := asn1.Marshal(tempAKI{KeyIdentifier: keyId})
	return cms.Extension{
		ObjectId:  oid.OidAuthorityKeyIdentifier,
		ExtnValue: asn1.RawValue{Bytes: encoded},
	}
}

// buildCert constructs a minimal Certificate for testing.
// raw provides the bytes used for fingerprinting; nil skiVal omits the SKI extension.
func buildCert(raw []byte, skiVal []byte, akiVal []byte) cms.Certificate {
	var exts cms.Extensions
	if skiVal != nil {
		exts = append(exts, buildSKIExt(skiVal))
	}
	if akiVal != nil {
		exts = append(exts, buildAKIExt(akiVal))
	}
	return cms.Certificate{
		Raw: asn1.RawContent(raw),
		TbsCertificate: cms.TBSCertificate{
			Extensions: exts,
		},
	}
}

// --- realMain ---

func TestRealMain_Success(t *testing.T) {
	var out, errOut strings.Builder
	code := realMain(&out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d; stderr: %s", code, errOut.String())
	}
	if !strings.HasPrefix(out.String(), "GMRTD:v") {
		t.Errorf("expected output to start with GMRTD:v, got: %.50s", out.String())
	}
}

func TestRealMain_GermanError(t *testing.T) {
	orig := germanMasterListFn
	t.Cleanup(func() { germanMasterListFn = orig })
	germanMasterListFn = func() (*cms.SignedDataCertPool, error) { return nil, fmt.Errorf("boom") }

	var out, errOut strings.Builder
	if code := realMain(&out, &errOut); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(errOut.String(), "German") {
		t.Errorf("expected 'German' in error output, got: %s", errOut.String())
	}
}

func TestRealMain_DutchError(t *testing.T) {
	orig := dutchMasterListFn
	t.Cleanup(func() { dutchMasterListFn = orig })
	dutchMasterListFn = func() (*cms.SignedDataCertPool, error) { return nil, fmt.Errorf("boom") }

	var out, errOut strings.Builder
	if code := realMain(&out, &errOut); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(errOut.String(), "Dutch") {
		t.Errorf("expected 'Dutch' in error output, got: %s", errOut.String())
	}
}

func TestRealMain_IndonesianError(t *testing.T) {
	orig := indonesian2010SeriesCertsFn
	t.Cleanup(func() { indonesian2010SeriesCertsFn = orig })
	indonesian2010SeriesCertsFn = func() (*cms.GenericCertPool, error) { return nil, fmt.Errorf("boom") }

	var out, errOut strings.Builder
	if code := realMain(&out, &errOut); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(errOut.String(), "Indonesian") {
		t.Errorf("expected 'Indonesian' in error output, got: %s", errOut.String())
	}
}

// --- CountryCerts.GetOrCreate ---

func TestGetOrCreate_SameRaw_ReturnsSameRecord(t *testing.T) {
	cc := NewCountryCerts()
	raw := []byte{1, 2, 3, 4, 5}

	cr1 := cc.GetOrCreate(buildCert(raw, []byte{0xAA}, nil))
	cr2 := cc.GetOrCreate(buildCert(raw, []byte{0xAA}, nil))

	if cr1 != cr2 {
		t.Errorf("expected the same CertRecord for identical raw bytes")
	}
	if len(cc.ByFingerprint) != 1 {
		t.Errorf("expected 1 entry, got %d", len(cc.ByFingerprint))
	}
}

func TestGetOrCreate_DifferentRaw_ReturnsDifferentRecords(t *testing.T) {
	cc := NewCountryCerts()

	cr1 := cc.GetOrCreate(buildCert([]byte{1, 2, 3}, []byte{0xAA}, nil))
	cr2 := cc.GetOrCreate(buildCert([]byte{4, 5, 6}, []byte{0xBB}, nil))

	if cr1 == cr2 {
		t.Errorf("expected different CertRecords for different raw bytes")
	}
	if len(cc.ByFingerprint) != 2 {
		t.Errorf("expected 2 entries, got %d", len(cc.ByFingerprint))
	}
}

func TestGetOrCreate_SourcesSharedAcrossDuplicates(t *testing.T) {
	cc := NewCountryCerts()
	raw := []byte{9, 8, 7}

	cr1 := cc.GetOrCreate(buildCert(raw, []byte{0xAA}, nil))
	cr1.Sources["DE"] = struct{}{}
	cr1.Sources["NL"] = struct{}{}

	cr2 := cc.GetOrCreate(buildCert(raw, []byte{0xAA}, nil))

	if len(cr2.Sources) != 2 {
		t.Errorf("expected 2 sources on deduplicated record, got %d", len(cr2.Sources))
	}
}

// --- isLinkCert ---

func TestIsLinkCert_NoAKI_ReturnsFalse(t *testing.T) {
	cert := buildCert([]byte{1}, []byte{0xAA, 0xBB}, nil)
	if isLinkCert(&cert) {
		t.Error("cert without AKI should not be a link cert")
	}
}

func TestIsLinkCert_AKIEqualsSKI_ReturnsFalse(t *testing.T) {
	id := []byte{0xAA, 0xBB, 0xCC}
	cert := buildCert([]byte{2}, id, id)
	if isLinkCert(&cert) {
		t.Error("self-signed cert (AKI == SKI) should not be a link cert")
	}
}

func TestIsLinkCert_AKIDifferentFromSKI_ReturnsTrue(t *testing.T) {
	cert := buildCert([]byte{3}, []byte{0xAA, 0xBB}, []byte{0x11, 0x22})
	if !isLinkCert(&cert) {
		t.Error("cert with AKI != SKI should be a link cert")
	}
}

func TestIsLinkCert_NilSKI_NoPanic(t *testing.T) {
	cert := buildCert([]byte{4}, nil, []byte{0x11, 0x22})
	if isLinkCert(&cert) {
		t.Error("cert without SKI should not be a link cert")
	}
}

// --- CountryCerts.BrokenLinkCerts ---

func TestBrokenLinkCerts_ValidLink_ReturnsEmpty(t *testing.T) {
	cc := NewCountryCerts()

	// CSCA: SKI = 0xAA, no AKI
	cr1 := cc.GetOrCreate(buildCert([]byte{10}, []byte{0xAA}, nil))
	cr1.Sources["DE"] = struct{}{}

	// Link cert: SKI = 0xBB, AKI = 0xAA (points to CSCA above)
	cr2 := cc.GetOrCreate(buildCert([]byte{20}, []byte{0xBB}, []byte{0xAA}))
	cr2.Sources["DE"] = struct{}{}

	broken := cc.BrokenLinkCerts()
	if len(broken) != 0 {
		t.Errorf("expected no broken links, got %d", len(broken))
	}
}

func TestBrokenLinkCerts_AKINotFound_ReturnsBroken(t *testing.T) {
	cc := NewCountryCerts()

	// CSCA: SKI = 0xAA
	cr1 := cc.GetOrCreate(buildCert([]byte{10}, []byte{0xAA}, nil))
	cr1.Sources["DE"] = struct{}{}

	// Link cert: AKI = 0xFF (no matching CSCA)
	cr2 := cc.GetOrCreate(buildCert([]byte{20}, []byte{0xBB}, []byte{0xFF}))
	cr2.Sources["DE"] = struct{}{}

	broken := cc.BrokenLinkCerts()
	if len(broken) != 1 {
		t.Errorf("expected 1 broken link, got %d", len(broken))
	}
}

func TestBrokenLinkCerts_NoLinkCerts_ReturnsEmpty(t *testing.T) {
	cc := NewCountryCerts()

	cr1 := cc.GetOrCreate(buildCert([]byte{10}, []byte{0xAA}, nil))
	cr1.Sources["DE"] = struct{}{}

	broken := cc.BrokenLinkCerts()
	if len(broken) != 0 {
		t.Errorf("expected no broken links when only CSCA certs present, got %d", len(broken))
	}
}

// --- AllCerts.GetOrCreate ---

func TestAllCertsGetOrCreate_CaseNormalisation(t *testing.T) {
	ac := NewAllCerts()

	cc1 := ac.GetOrCreate("de")
	cc2 := ac.GetOrCreate("DE")

	if cc1 != cc2 {
		t.Error("expected same CountryCerts for different case of the same country code")
	}
	if len(ac.ByCountry) != 1 {
		t.Errorf("expected 1 country entry, got %d", len(ac.ByCountry))
	}
}

// --- formatSources ---

func TestFormatSources_Single(t *testing.T) {
	result := formatSources(map[string]struct{}{"DE": {}})
	if result != "[DE]" {
		t.Errorf("expected [DE], got %s", result)
	}
}

func TestFormatSources_MultipleSorted(t *testing.T) {
	sources := map[string]struct{}{"NL": {}, "DE": {}, "IDN-2010": {}}
	result := formatSources(sources)
	if result != "[DE,IDN-2010,NL]" {
		t.Errorf("expected [DE,IDN-2010,NL], got %s", result)
	}
}

// --- formatValidity ---

func TestFormatValidity_ValidDates(t *testing.T) {
	notBefore := time.Date(2020, 1, 15, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC)

	nbEncoded, _ := asn1.Marshal(notBefore)
	naEncoded, _ := asn1.Marshal(notAfter)

	validity := cms.Validity{
		NotBefore: asn1.RawValue{FullBytes: nbEncoded},
		NotAfter:  asn1.RawValue{FullBytes: naEncoded},
	}

	result := formatValidity(validity)
	expected := "2020-01-15..2030-12-31"
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestFormatValidity_EmptyRaw_ReturnsPlaceholder(t *testing.T) {
	validity := cms.Validity{}
	result := formatValidity(validity)
	if result != "?..?" {
		t.Errorf("expected ?..? for empty validity, got %s", result)
	}
}

// --- sortedFingerprints ---

func TestSortedFingerprints_Empty(t *testing.T) {
	result := sortedFingerprints(map[string]*CertRecord{})
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %v", result)
	}
}

func TestSortedFingerprints_Sorted(t *testing.T) {
	m := map[string]*CertRecord{"cc": {}, "aa": {}, "bb": {}}
	result := sortedFingerprints(m)
	if len(result) != 3 || result[0] != "aa" || result[1] != "bb" || result[2] != "cc" {
		t.Errorf("expected [aa bb cc], got %v", result)
	}
}

// --- skiHex ---

func TestSkiHex_WithSKI(t *testing.T) {
	cert := buildCert([]byte{1}, []byte{0xAA, 0xBB}, nil)
	if got := skiHex(&cert); got != "AABB" {
		t.Errorf("expected AABB, got %s", got)
	}
}

func TestSkiHex_NoSKI(t *testing.T) {
	cert := buildCert([]byte{1}, nil, nil)
	if got := skiHex(&cert); got != "?" {
		t.Errorf("expected ?, got %s", got)
	}
}

// --- subjectDN ---

// buildSubjectRDN encodes an RDNSequence from a list of (OID, value) pairs.
func buildSubjectRDN(attrs []struct {
	oid   asn1.ObjectIdentifier
	value string
}) asn1.RawValue {
	var rdnSets []byte
	for _, attr := range attrs {
		oidBytes, _ := asn1.Marshal(attr.oid)
		valBytes, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(attr.value)})
		attrContent := append(oidBytes, valBytes...)
		attrSeq := append([]byte{0x30, byte(len(attrContent))}, attrContent...)
		rdnSet := append([]byte{0x31, byte(len(attrSeq))}, attrSeq...)
		rdnSets = append(rdnSets, rdnSet...)
	}
	rdnSeq := append([]byte{0x30, byte(len(rdnSets))}, rdnSets...)
	return asn1.RawValue{FullBytes: rdnSeq}
}

func TestSubjectDN_WithCN(t *testing.T) {
	subject := buildSubjectRDN([]struct {
		oid   asn1.ObjectIdentifier
		value string
	}{{oid.OidCommonName, "TestCert"}})
	cert := cms.Certificate{
		Raw: asn1.RawContent([]byte{1}),
		TbsCertificate: cms.TBSCertificate{
			Subject: subject,
		},
	}
	if got := subjectDN(&cert); got != "CN=TestCert" {
		t.Errorf("expected CN=TestCert, got %s", got)
	}
}

func TestSubjectDN_EmptySubject(t *testing.T) {
	cert := buildCert([]byte{1}, []byte{0xAA}, nil)
	if got := subjectDN(&cert); got != "?" {
		t.Errorf("expected ?, got %s", got)
	}
}

func TestSubjectDN_OrgOnly(t *testing.T) {
	subject := buildSubjectRDN([]struct {
		oid   asn1.ObjectIdentifier
		value string
	}{{oid.OidOrganizationName, "U.S. Department of State"}})
	cert := cms.Certificate{
		Raw: asn1.RawContent([]byte{1}),
		TbsCertificate: cms.TBSCertificate{
			Subject: subject,
		},
	}
	if got := subjectDN(&cert); got != "O=U.S. Department of State" {
		t.Errorf("expected 'O=U.S. Department of State', got %s", got)
	}
}

func TestSubjectDN_MultipleAttributes(t *testing.T) {
	subject := buildSubjectRDN([]struct {
		oid   asn1.ObjectIdentifier
		value string
	}{
		{oid.OidCountryName, "US"},
		{oid.OidOrganizationName, "U.S. Department of State"},
		{oid.OidCommonName, "CSCA_US"},
	})
	cert := cms.Certificate{
		Raw: asn1.RawContent([]byte{1}),
		TbsCertificate: cms.TBSCertificate{
			Subject: subject,
		},
	}
	expected := "CN=CSCA_US, O=U.S. Department of State, C=US"
	if got := subjectDN(&cert); got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

// --- formatKeyType ---

// buildCertWithSPKI creates a Certificate with the given raw SPKI bytes.
func buildCertWithSPKI(spkiBytes []byte) cms.Certificate {
	return cms.Certificate{
		Raw: asn1.RawContent([]byte{1}),
		TbsCertificate: cms.TBSCertificate{
			SubjectPublicKeyInfo: asn1.RawValue{FullBytes: spkiBytes},
		},
	}
}

// buildECSPKIBytes encodes a SubjectPublicKeyInfo for an EC key with the given named-curve OID.
func buildECSPKIBytes(curveOID asn1.ObjectIdentifier) []byte {
	curveOIDBytes, _ := asn1.Marshal(curveOID)
	spki := cms.SubjectPublicKeyInfo{
		Algorithm: cms.AlgorithmIdentifier{
			Algorithm:  oid.OidEcPublicKey,
			Parameters: asn1.RawValue{FullBytes: curveOIDBytes},
		},
		SubjectPublicKey: asn1.BitString{Bytes: []byte{0x04, 0x01, 0x02}},
	}
	b, _ := asn1.Marshal(spki)
	return b
}

// buildRSASPKIBytes encodes a SubjectPublicKeyInfo for an RSA key with the given modulus and exponent.
func buildRSASPKIBytes(n *big.Int, e int) []byte {
	type rsaKey struct {
		N *big.Int
		E int
	}
	keyBytes, _ := asn1.Marshal(rsaKey{N: n, E: e})
	spki := cms.SubjectPublicKeyInfo{
		Algorithm:        cms.AlgorithmIdentifier{Algorithm: oid.OidRsaEncryption},
		SubjectPublicKey: asn1.BitString{Bytes: keyBytes},
	}
	b, _ := asn1.Marshal(spki)
	return b
}

func TestFormatKeyType_InvalidSPKI(t *testing.T) {
	cert := buildCertWithSPKI([]byte{0xFF, 0xFF})
	if got := formatKeyType(&cert); got != "?" {
		t.Errorf("expected ?, got %s", got)
	}
}

func TestFormatKeyType_NilSPKI(t *testing.T) {
	cert := buildCertWithSPKI(nil)
	if got := formatKeyType(&cert); got != "?" {
		t.Errorf("expected ?, got %s", got)
	}
}

func TestFormatKeyType_ECNamedCurve_P256(t *testing.T) {
	cert := buildCertWithSPKI(buildECSPKIBytes(oid.OidPrime256v1))
	if got := formatKeyType(&cert); got != "EC(P-256)" {
		t.Errorf("expected EC(P-256), got %s", got)
	}
}

func TestFormatKeyType_ECUnknownCurve(t *testing.T) {
	// Use OidRsaEncryption as a fake curve OID — not in the named-curve table.
	cert := buildCertWithSPKI(buildECSPKIBytes(oid.OidRsaEncryption))
	if got := formatKeyType(&cert); got != "EC(?)" {
		t.Errorf("expected EC(?), got %s", got)
	}
}

func TestFormatKeyType_ECNoCurveParam(t *testing.T) {
	// EC SPKI with no Parameters → EcCurve fails.
	spki := cms.SubjectPublicKeyInfo{
		Algorithm:        cms.AlgorithmIdentifier{Algorithm: oid.OidEcPublicKey},
		SubjectPublicKey: asn1.BitString{Bytes: []byte{0x04, 0x01, 0x02}},
	}
	b, _ := asn1.Marshal(spki)
	cert := buildCertWithSPKI(b)
	if got := formatKeyType(&cert); got != "EC(?)" {
		t.Errorf("expected EC(?), got %s", got)
	}
}

func TestFormatKeyType_RSAValid(t *testing.T) {
	// 512-bit modulus (64 bytes of 0xFF), odd exponent 65537.
	n := new(big.Int).SetBytes(bytes.Repeat([]byte{0xFF}, 64))
	cert := buildCertWithSPKI(buildRSASPKIBytes(n, 65537))
	if got := formatKeyType(&cert); got != "RSA(512)" {
		t.Errorf("expected RSA(512), got %s", got)
	}
}

func TestFormatKeyType_RSABadKey(t *testing.T) {
	spki := cms.SubjectPublicKeyInfo{
		Algorithm:        cms.AlgorithmIdentifier{Algorithm: oid.OidRsaEncryption},
		SubjectPublicKey: asn1.BitString{Bytes: []byte{0xFF, 0xFF}},
	}
	b, _ := asn1.Marshal(spki)
	cert := buildCertWithSPKI(b)
	if got := formatKeyType(&cert); got != "RSA(?)" {
		t.Errorf("expected RSA(?), got %s", got)
	}
}

func TestFormatKeyType_UnknownAlgorithm(t *testing.T) {
	spki := cms.SubjectPublicKeyInfo{
		Algorithm: cms.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}},
	}
	b, _ := asn1.Marshal(spki)
	cert := buildCertWithSPKI(b)
	if got := formatKeyType(&cert); got != "?" {
		t.Errorf("expected ?, got %s", got)
	}
}

// --- run() ---

type mockCertPool map[string][]cms.Certificate

func (m mockCertPool) ByIssuerCountry(alpha2 string) []cms.Certificate    { return m[alpha2] }
func (m mockCertPool) BySKI(_ []byte) []cms.Certificate                   { return nil }
func (m mockCertPool) ByIssuerAndSerial(_ []byte) ([]cms.Certificate, error) { return nil, nil }
func (m mockCertPool) All() []cms.Certificate {
	var all []cms.Certificate
	for _, certs := range m {
		all = append(all, certs...)
	}
	return all
}

func TestRun_EmptyPools(t *testing.T) {
	var buf strings.Builder
	countries := []iso3166.Country{{Alpha2: "DE", Name: "Germany"}}
	run(nil, countries, &buf)
	out := buf.String()
	if strings.Contains(out, "[DE]") {
		t.Error("expected no country block for empty pools")
	}
	if !strings.Contains(out, "CSCA certificate count (unique): 0") {
		t.Errorf("expected zero CSCA count in summary:\n%s", out)
	}
}

func TestRun_SingleCSCA(t *testing.T) {
	var buf strings.Builder
	cert := buildCert([]byte{1, 2, 3}, []byte{0xAA}, nil)
	pool := mockCertPool{"DE": {cert}}
	countries := []iso3166.Country{{Alpha2: "DE", Name: "Germany"}}
	run([]namedPool{{name: "TEST", pool: pool}}, countries, &buf)
	out := buf.String()
	if !strings.Contains(out, "[DE]") {
		t.Errorf("expected [DE] country block:\n%s", out)
	}
	if !strings.Contains(out, "CSCA certificate count (unique): 1") {
		t.Errorf("expected 1 CSCA cert in summary:\n%s", out)
	}
}

func TestRun_LinkCert(t *testing.T) {
	var buf strings.Builder
	csca := buildCert([]byte{1}, []byte{0xAA}, nil)
	link := buildCert([]byte{2}, []byte{0xBB}, []byte{0xAA})
	pool := mockCertPool{"DE": {csca, link}}
	countries := []iso3166.Country{{Alpha2: "DE", Name: "Germany"}}
	run([]namedPool{{name: "TEST", pool: pool}}, countries, &buf)
	out := buf.String()
	if !strings.Contains(out, "Link certificate count (unique): 1") {
		t.Errorf("expected 1 link cert in summary:\n%s", out)
	}
	if !strings.Contains(out, "Broken link count:               0") {
		t.Errorf("expected 0 broken links:\n%s", out)
	}
}

func TestRun_BrokenLink(t *testing.T) {
	var buf strings.Builder
	csca := buildCert([]byte{1}, []byte{0xAA}, nil)
	broken := buildCert([]byte{2}, []byte{0xBB}, []byte{0xFF}) // AKI 0xFF has no matching CSCA
	pool := mockCertPool{"DE": {csca, broken}}
	countries := []iso3166.Country{{Alpha2: "DE", Name: "Germany"}}
	run([]namedPool{{name: "TEST", pool: pool}}, countries, &buf)
	out := buf.String()
	if !strings.Contains(out, "BROKEN LINKS") {
		t.Errorf("expected BROKEN LINKS section:\n%s", out)
	}
	if !strings.Contains(out, "Broken link count:               1") {
		t.Errorf("expected 1 broken link in summary:\n%s", out)
	}
}

func TestRun_MultipleBrokenLinks(t *testing.T) {
	// Two broken links forces the sort comparator to be called.
	var buf strings.Builder
	csca := buildCert([]byte{1}, []byte{0xAA}, nil)
	broken1 := buildCert([]byte{2}, []byte{0xBB}, []byte{0xFF})
	broken2 := buildCert([]byte{3}, []byte{0xCC}, []byte{0xFE})
	pool := mockCertPool{"DE": {csca, broken1, broken2}}
	countries := []iso3166.Country{{Alpha2: "DE", Name: "Germany"}}
	run([]namedPool{{name: "TEST", pool: pool}}, countries, &buf)
	out := buf.String()
	if !strings.Contains(out, "Broken link count:               2") {
		t.Errorf("expected 2 broken links in summary:\n%s", out)
	}
}

func TestRun_DuplicateCertAcrossPools(t *testing.T) {
	var buf strings.Builder
	cert := buildCert([]byte{1, 2, 3}, []byte{0xAA}, nil)
	pool1 := mockCertPool{"DE": {cert}}
	pool2 := mockCertPool{"DE": {cert}}
	countries := []iso3166.Country{{Alpha2: "DE", Name: "Germany"}}
	pools := []namedPool{{name: "P1", pool: pool1}, {name: "P2", pool: pool2}}
	run(pools, countries, &buf)
	out := buf.String()
	if !strings.Contains(out, "CSCA certificate count (unique): 1") {
		t.Errorf("expected 1 unique cert (not 2):\n%s", out)
	}
	if !strings.Contains(out, "[P1,P2]") {
		t.Errorf("expected both sources [P1,P2]:\n%s", out)
	}
}

func TestRun_MultipleCountries(t *testing.T) {
	var buf strings.Builder
	certDE := buildCert([]byte{1}, []byte{0xAA}, nil)
	certNL := buildCert([]byte{2}, []byte{0xBB}, nil)
	pool := mockCertPool{"DE": {certDE}, "NL": {certNL}}
	countries := []iso3166.Country{
		{Alpha2: "DE", Name: "Germany"},
		{Alpha2: "NL", Name: "Netherlands"},
	}
	run([]namedPool{{name: "TEST", pool: pool}}, countries, &buf)
	out := buf.String()
	if !strings.Contains(out, "Countries with CSCA certificates: 2") {
		t.Errorf("expected 2 countries with CSCA certs:\n%s", out)
	}
}
