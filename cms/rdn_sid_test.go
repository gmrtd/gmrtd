package cms

import (
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

// helper to build an Attribute with the given OID and UTF8String value
func makeAttr(oidVal asn1.ObjectIdentifier, value string) Attribute {
	valueBytes, _ := asn1.Marshal(value)
	return Attribute{
		Type:   oidVal,
		Values: asn1.RawValue{FullBytes: valueBytes, Tag: int(valueBytes[0]) & 0x1f, Bytes: []byte(value)},
	}
}

// ---------------------------------------------------------------------------
// RDNSequence.Equal
// ---------------------------------------------------------------------------

func TestRDNSequenceEqualIdentical(t *testing.T) {
	t.Parallel()
	a := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidCountryName, "DE")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidOrganizationName, "bund")},
	}
	b := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidCountryName, "DE")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidOrganizationName, "bund")},
	}
	if !a.Equal(b) {
		t.Fatal("identical RDN sequences should be equal")
	}
}

func TestRDNSequenceEqualDifferentOrder(t *testing.T) {
	t.Parallel()
	a := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidCountryName, "MY")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidOrganizationName, "Jabatan")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidCommonName, "Malaysia Country Signer")},
	}
	b := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidOrganizationName, "Jabatan")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidCommonName, "Malaysia Country Signer")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidCountryName, "MY")},
	}
	if !a.Equal(b) {
		t.Fatal("RDN sequences with same attrs in different order should be equal")
	}
}

func TestRDNSequenceEqualDifferentCount(t *testing.T) {
	t.Parallel()
	a := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidCountryName, "DE")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidOrganizationName, "bund")},
	}
	b := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidCountryName, "DE")},
	}
	if a.Equal(b) {
		t.Fatal("RDN sequences with different attribute counts should not be equal")
	}
}

func TestRDNSequenceEqualDifferentValue(t *testing.T) {
	t.Parallel()
	a := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidCountryName, "DE")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidOrganizationName, "bund")},
	}
	b := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidCountryName, "DE")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidOrganizationName, "other")},
	}
	if a.Equal(b) {
		t.Fatal("RDN sequences with different values should not be equal")
	}
}

func TestRDNSequenceEqualDifferentOID(t *testing.T) {
	t.Parallel()
	a := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidCountryName, "DE")},
	}
	b := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidOrganizationName, "DE")},
	}
	if a.Equal(b) {
		t.Fatal("RDN sequences with different OIDs should not be equal")
	}
}

func TestRDNSequenceEqualBothEmpty(t *testing.T) {
	t.Parallel()
	a := RDNSequence{}
	b := RDNSequence{}
	if !a.Equal(b) {
		t.Fatal("two empty RDN sequences should be equal")
	}
}

func TestRDNSequenceEqualMultiValuedSET(t *testing.T) {
	t.Parallel()
	// Multi-valued RDN SET (multiple attrs in one SET)
	a := RDNSequence{
		RelativeDistinguishedNameSET{
			makeAttr(oid.OidCountryName, "DE"),
			makeAttr(oid.OidOrganizationName, "bund"),
		},
	}
	b := RDNSequence{
		RelativeDistinguishedNameSET{
			makeAttr(oid.OidOrganizationName, "bund"),
			makeAttr(oid.OidCountryName, "DE"),
		},
	}
	if !a.Equal(b) {
		t.Fatal("multi-valued SETs with same attrs in different order should be equal")
	}
}

// ---------------------------------------------------------------------------
// RDNSequence.Equal - normalized string matching (issue #440)
//
// The SignerInfo issuer copy and the embedded DS certificate issuer can encode
// the same Distinguished Name with a different DER string type, letter case, or
// insignificant whitespace. These must still compare equal so the DS cert can be
// selected from the SOD.
// ---------------------------------------------------------------------------

const (
	tagUTF8String      = 12
	tagPrintableString = 19
	tagBMPString       = 30
)

// makeAttrTagged builds an Attribute whose value uses an explicit universal
// string tag (short-form length; sufficient for test values).
func makeAttrTagged(oidVal asn1.ObjectIdentifier, tag int, content []byte) Attribute {
	full := append([]byte{byte(tag), byte(len(content))}, content...)
	return Attribute{
		Type:   oidVal,
		Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, Bytes: content, FullBytes: full},
	}
}

func bmpBytes(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r>>8), byte(r&0xff))
	}
	return out
}

func TestRDNSequenceEqualDifferentStringEncoding(t *testing.T) {
	t.Parallel()
	// Same DN, but one side is PrintableString and the other UTF8String.
	a := RDNSequence{
		RelativeDistinguishedNameSET{makeAttrTagged(oid.OidCommonName, tagPrintableString, []byte("CSCA-UKRAINE"))},
	}
	b := RDNSequence{
		RelativeDistinguishedNameSET{makeAttrTagged(oid.OidCommonName, tagUTF8String, []byte("CSCA-UKRAINE"))},
	}
	if !a.Equal(b) {
		t.Fatal("same DN with PrintableString vs UTF8String encoding should be equal")
	}
}

func TestRDNSequenceEqualCaseInsensitive(t *testing.T) {
	t.Parallel()
	a := RDNSequence{
		RelativeDistinguishedNameSET{makeAttrTagged(oid.OidOrganizationName, tagPrintableString, []byte("bund"))},
	}
	b := RDNSequence{
		RelativeDistinguishedNameSET{makeAttrTagged(oid.OidOrganizationName, tagUTF8String, []byte("BUND"))},
	}
	if !a.Equal(b) {
		t.Fatal("DN differing only in letter case should be equal")
	}
}

func TestRDNSequenceEqualWhitespaceInsensitive(t *testing.T) {
	t.Parallel()
	a := RDNSequence{
		RelativeDistinguishedNameSET{makeAttrTagged(oid.OidCommonName, tagPrintableString, []byte("Malaysia  Country Signer"))},
	}
	b := RDNSequence{
		RelativeDistinguishedNameSET{makeAttrTagged(oid.OidCommonName, tagPrintableString, []byte(" Malaysia Country Signer "))},
	}
	if !a.Equal(b) {
		t.Fatal("DN differing only in insignificant whitespace should be equal")
	}
}

func TestRDNSequenceEqualBMPString(t *testing.T) {
	t.Parallel()
	a := RDNSequence{
		RelativeDistinguishedNameSET{makeAttrTagged(oid.OidCommonName, tagBMPString, bmpBytes("CSCA-UKRAINE"))},
	}
	b := RDNSequence{
		RelativeDistinguishedNameSET{makeAttrTagged(oid.OidCommonName, tagUTF8String, []byte("CSCA-UKRAINE"))},
	}
	if !a.Equal(b) {
		t.Fatal("same DN encoded as BMPString vs UTF8String should be equal")
	}
}

func TestRDNSequenceEqualDifferentValueStillUnequal(t *testing.T) {
	t.Parallel()
	// Guard: normalization must not collapse genuinely different values.
	a := RDNSequence{
		RelativeDistinguishedNameSET{makeAttrTagged(oid.OidCommonName, tagPrintableString, []byte("CSCA-UKRAINE"))},
	}
	b := RDNSequence{
		RelativeDistinguishedNameSET{makeAttrTagged(oid.OidCommonName, tagUTF8String, []byte("CSCA-GERMANY"))},
	}
	if a.Equal(b) {
		t.Fatal("different common names must not be equal despite encoding normalization")
	}
}

// ---------------------------------------------------------------------------
// RDNSequence.Flatten
// ---------------------------------------------------------------------------

func TestRDNSequenceFlattenEmpty(t *testing.T) {
	t.Parallel()
	rdnSeq := RDNSequence{}
	got := rdnSeq.Flatten()
	if len(got) != 0 {
		t.Fatalf("expected 0 attrs, got %d", len(got))
	}
}

func TestRDNSequenceFlattenMultipleSets(t *testing.T) {
	t.Parallel()
	rdnSeq := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidCountryName, "DE")},
		RelativeDistinguishedNameSET{
			makeAttr(oid.OidOrganizationName, "bund"),
			makeAttr(oid.OidCommonName, "csca-germany"),
		},
	}
	got := rdnSeq.Flatten()
	if len(got) != 3 {
		t.Fatalf("expected 3 attrs, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// RDNSequence.String
// ---------------------------------------------------------------------------

func TestRDNSequenceStringEmpty(t *testing.T) {
	t.Parallel()
	rdnSeq := RDNSequence{}
	if got := rdnSeq.String(); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestRDNSequenceStringSingleCN(t *testing.T) {
	t.Parallel()
	rdnSeq := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidCommonName, "csca-germany")},
	}
	expected := "CN=csca-germany"
	if got := rdnSeq.String(); got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestRDNSequenceStringMultipleAttrs(t *testing.T) {
	t.Parallel()
	rdnSeq := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidCountryName, "US")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidOrganizationName, "U.S. Government")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidOrganizationalUnitName, "Department of State")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidCommonName, "CSCA_US")},
	}
	expected := "CN=CSCA_US, OU=Department of State, O=U.S. Government, C=US"
	if got := rdnSeq.String(); got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestRDNSequenceStringAllKnownOIDs(t *testing.T) {
	t.Parallel()
	rdnSeq := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidCountryName, "DE")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidStateOrProvinceName, "Berlin")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidLocalityName, "Berlin")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidOrganizationName, "bund")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidOrganizationalUnitName, "bsi")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidSerialNumber, "001")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidCommonName, "csca-germany")},
	}
	expected := "CN=csca-germany, SERIALNUMBER=001, OU=bsi, O=bund, L=Berlin, ST=Berlin, C=DE"
	if got := rdnSeq.String(); got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestRDNSequenceStringUnknownOID(t *testing.T) {
	t.Parallel()
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	rdnSeq := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidCountryName, "FR")},
		RelativeDistinguishedNameSET{makeAttr(unknownOID, "something")},
	}
	expected := "1.2.3.4.5=something, C=FR"
	if got := rdnSeq.String(); got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestRDNSequenceStringMultiValuedSET(t *testing.T) {
	t.Parallel()
	rdnSeq := RDNSequence{
		RelativeDistinguishedNameSET{
			makeAttr(oid.OidCountryName, "DE"),
			makeAttr(oid.OidOrganizationName, "bund"),
		},
	}
	expected := "O=bund, C=DE"
	if got := rdnSeq.String(); got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestRDNSequenceStringEscaping(t *testing.T) {
	t.Parallel()
	rdnSeq := RDNSequence{
		RelativeDistinguishedNameSET{makeAttr(oid.OidCommonName, `val+with,special"chars`)},
		RelativeDistinguishedNameSET{makeAttr(oid.OidOrganizationName, "#leading hash")},
		RelativeDistinguishedNameSET{makeAttr(oid.OidOrganizationalUnitName, " spaces ")},
	}
	expected := `OU=\ spaces\ , O=\#leading hash, CN=val\+with\,special\"chars`
	if got := rdnSeq.String(); got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

// ---------------------------------------------------------------------------
// selectCertificate – unsupported SID tag
// ---------------------------------------------------------------------------

func TestSelectCertificateUnsupportedSIDTag(t *testing.T) {
	t.Parallel()

	// Use real cert bytes from the AT test case
	certBytes := utils.HexToBytes("308203df30820366a00302010202086189db18b6ede857300a06082a8648ce3d040303303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941301e170d3233303133313038303430325a170d3333303530363038303430325a3054310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d49310f300d060355040513063030343031353119301706035504030c1044532d415553545249412d654d525444308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200048893905193f315ee2e2f1eee3fd5a496f6637deb3778cfe7cc2f6c7f0682acc795b0290265a2cb83119343544f2bbfe42974159ac77b113dafbee860c2523c06a382015930820155301d0603551d0e04160414e76eaa567acf6568c660c985717c3c8a50bd024b301f0603551d230418301680142692c7e398abfbe35192d3f26e9a317d1fed53bd301a0603551d1004133011810f32303233303530363038303430325a30160603551d20040f300d300b06092a28000a0102010101303e0603551d1f043730353033a031a02f862d687474703a2f2f7777772e626d692e67762e61742f637363612f63726c2f43534341415553545249412e63726c300e0603551d0f0101ff04040302078030370603551d120430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f30370603551d110430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f301d06076781080101060204123010020100310b1301501302415213024944300a06082a8648ce3d040303036700306402303af7ae31ca6b8fafca6ec51985997f7119fb2e6d20d61b5327d5740109aa310b410bfb44f354e086f207fcab721e69ae023046c68fb7909f994350a2d1c84d1ae5dff8c00de6d86b7891a6cf90ceea09159402e6e2ed3fa548db28d33146319eefda")

	sd := &SignedData{
		SignerInfos: []SignerInfo{
			{
				// Tag 5, Class APPLICATION = unsupported
				Sid: asn1.RawValue{Tag: 5, Class: asn1.ClassApplication, Bytes: []byte{0x01}},
			},
		},
		Certificates: asn1.RawValue{Bytes: certBytes},
	}

	si := &sd.SignerInfos[0]
	cert, err := si.selectCertificate(sd)
	if err == nil {
		t.Fatal("expected error for unsupported SID tag")
	}
	if cert != nil {
		t.Fatal("cert should be nil on error")
	}
	if got := err.Error(); !contains(got, "unsupported SignerIdentifier") {
		t.Fatalf("unexpected error message: %s", got)
	}
}

// ---------------------------------------------------------------------------
// selectCertificate – IssuerAndSerialNumber SID with no matching cert
// ---------------------------------------------------------------------------

// When the IssuerAndSerialNumber SID matches no embedded cert but the SOD embeds
// exactly one certificate, selectCertificate falls back to that sole cert (issue
// #440, JMRTD-style). Trust remains gated by the downstream signature and
// CSCA-chain checks.
func TestSelectCertificateIssuerSerialNoMatchFallsBackToSoleCert(t *testing.T) {
	t.Parallel()

	certBytes := utils.HexToBytes("308203df30820366a00302010202086189db18b6ede857300a06082a8648ce3d040303303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941301e170d3233303133313038303430325a170d3333303530363038303430325a3054310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d49310f300d060355040513063030343031353119301706035504030c1044532d415553545249412d654d525444308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200048893905193f315ee2e2f1eee3fd5a496f6637deb3778cfe7cc2f6c7f0682acc795b0290265a2cb83119343544f2bbfe42974159ac77b113dafbee860c2523c06a382015930820155301d0603551d0e04160414e76eaa567acf6568c660c985717c3c8a50bd024b301f0603551d230418301680142692c7e398abfbe35192d3f26e9a317d1fed53bd301a0603551d1004133011810f32303233303530363038303430325a30160603551d20040f300d300b06092a28000a0102010101303e0603551d1f043730353033a031a02f862d687474703a2f2f7777772e626d692e67762e61742f637363612f63726c2f43534341415553545249412e63726c300e0603551d0f0101ff04040302078030370603551d120430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f30370603551d110430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f301d06076781080101060204123010020100310b1301501302415213024944300a06082a8648ce3d040303036700306402303af7ae31ca6b8fafca6ec51985997f7119fb2e6d20d61b5327d5740109aa310b410bfb44f354e086f207fcab721e69ae023046c68fb7909f994350a2d1c84d1ae5dff8c00de6d86b7891a6cf90ceea09159402e6e2ed3fa548db28d33146319eefda")

	// Build an IssuerAndSerialNumber that won't match the cert (wrong serial)
	issuerAndSerial, _ := asn1.Marshal(struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}{
		Issuer:       asn1.RawValue{FullBytes: utils.HexToBytes("303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941")},
		SerialNumber: big.NewInt(9999999999),
	})

	sd := &SignedData{
		SignerInfos: []SignerInfo{
			{
				Sid: asn1.RawValue{Tag: asn1.TagSequence, Class: asn1.ClassUniversal, IsCompound: true, FullBytes: issuerAndSerial},
			},
		},
		Certificates: asn1.RawValue{Bytes: certBytes},
	}

	si := &sd.SignerInfos[0]
	cert, err := si.selectCertificate(sd)
	if err != nil {
		t.Fatalf("expected fallback to the sole embedded cert, got error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected the sole embedded cert, got nil")
	}
	// AT DS cert serial 0x6189db18b6ede857
	expSerial, _ := new(big.Int).SetString("6189db18b6ede857", 16)
	if cert.TbsCertificate.SerialNumber.Cmp(expSerial) != 0 {
		t.Errorf("unexpected cert selected (serial %x)", cert.TbsCertificate.SerialNumber)
	}
}

// ---------------------------------------------------------------------------
// selectCertificate – malformed IssuerAndSerialNumber
// ---------------------------------------------------------------------------

func TestSelectCertificateMalformedIssuerSerial(t *testing.T) {
	t.Parallel()

	certBytes := utils.HexToBytes("308203df30820366a00302010202086189db18b6ede857300a06082a8648ce3d040303303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941301e170d3233303133313038303430325a170d3333303530363038303430325a3054310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d49310f300d060355040513063030343031353119301706035504030c1044532d415553545249412d654d525444308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200048893905193f315ee2e2f1eee3fd5a496f6637deb3778cfe7cc2f6c7f0682acc795b0290265a2cb83119343544f2bbfe42974159ac77b113dafbee860c2523c06a382015930820155301d0603551d0e04160414e76eaa567acf6568c660c985717c3c8a50bd024b301f0603551d230418301680142692c7e398abfbe35192d3f26e9a317d1fed53bd301a0603551d1004133011810f32303233303530363038303430325a30160603551d20040f300d300b06092a28000a0102010101303e0603551d1f043730353033a031a02f862d687474703a2f2f7777772e626d692e67762e61742f637363612f63726c2f43534341415553545249412e63726c300e0603551d0f0101ff04040302078030370603551d120430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f30370603551d110430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f301d06076781080101060204123010020100310b1301501302415213024944300a06082a8648ce3d040303036700306402303af7ae31ca6b8fafca6ec51985997f7119fb2e6d20d61b5327d5740109aa310b410bfb44f354e086f207fcab721e69ae023046c68fb7909f994350a2d1c84d1ae5dff8c00de6d86b7891a6cf90ceea09159402e6e2ed3fa548db28d33146319eefda")

	// Malformed: tag says SEQUENCE but content is garbage
	malformedSid := []byte{0x30, 0x04, 0xDE, 0xAD, 0xBE, 0xEF}

	sd := &SignedData{
		SignerInfos: []SignerInfo{
			{
				Sid: asn1.RawValue{Tag: asn1.TagSequence, Class: asn1.ClassUniversal, IsCompound: true, FullBytes: malformedSid},
			},
		},
		Certificates: asn1.RawValue{Bytes: certBytes},
	}

	si := &sd.SignerInfos[0]
	cert, err := si.selectCertificate(sd)
	if err == nil {
		t.Fatal("expected error for malformed IssuerAndSerialNumber")
	}
	if cert != nil {
		t.Fatal("cert should be nil on error")
	}
	if got := err.Error(); !contains(got, "ByIssuerAndSerial") {
		t.Fatalf("unexpected error message: %s", got)
	}
}

// ---------------------------------------------------------------------------
// GenericCertPool.ByIssuerAndSerial – malformed input
// ---------------------------------------------------------------------------

func TestByIssuerAndSerialMalformedInput(t *testing.T) {
	t.Parallel()

	pool := &GenericCertPool{}
	_, err := pool.ByIssuerAndSerial([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	if err == nil {
		t.Fatal("expected error for malformed input")
	}
	if got := err.Error(); !contains(got, "unmarshal IssuerAndSerialNumber") {
		t.Fatalf("unexpected error message: %s", got)
	}
}

func TestByIssuerAndSerialNoMatch(t *testing.T) {
	t.Parallel()

	pool := &GenericCertPool{}
	pool.Add(utils.HexToBytes("308203df30820366a00302010202086189db18b6ede857300a06082a8648ce3d040303303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941301e170d3233303133313038303430325a170d3333303530363038303430325a3054310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d49310f300d060355040513063030343031353119301706035504030c1044532d415553545249412d654d525444308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200048893905193f315ee2e2f1eee3fd5a496f6637deb3778cfe7cc2f6c7f0682acc795b0290265a2cb83119343544f2bbfe42974159ac77b113dafbee860c2523c06a382015930820155301d0603551d0e04160414e76eaa567acf6568c660c985717c3c8a50bd024b301f0603551d230418301680142692c7e398abfbe35192d3f26e9a317d1fed53bd301a0603551d1004133011810f32303233303530363038303430325a30160603551d20040f300d300b06092a28000a0102010101303e0603551d1f043730353033a031a02f862d687474703a2f2f7777772e626d692e67762e61742f637363612f63726c2f43534341415553545249412e63726c300e0603551d0f0101ff04040302078030370603551d120430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f30370603551d110430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f301d06076781080101060204123010020100310b1301501302415213024944300a06082a8648ce3d040303036700306402303af7ae31ca6b8fafca6ec51985997f7119fb2e6d20d61b5327d5740109aa310b410bfb44f354e086f207fcab721e69ae023046c68fb7909f994350a2d1c84d1ae5dff8c00de6d86b7891a6cf90ceea09159402e6e2ed3fa548db28d33146319eefda"))

	// Build IssuerAndSerialNumber with a serial that doesn't match
	issuerAndSerial, _ := asn1.Marshal(struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}{
		Issuer:       asn1.RawValue{FullBytes: utils.HexToBytes("303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941")},
		SerialNumber: big.NewInt(1),
	})

	certs, err := pool.ByIssuerAndSerial(issuerAndSerial)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected 0 matching certs, got %d", len(certs))
	}
}

func TestByIssuerAndSerialExactMatch(t *testing.T) {
	t.Parallel()

	// AT cert with serial 0x6189db18b6ede857 and issuer "CSCA-AUSTRIA"
	pool := &GenericCertPool{}
	pool.Add(utils.HexToBytes("308203df30820366a00302010202086189db18b6ede857300a06082a8648ce3d040303303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941301e170d3233303133313038303430325a170d3333303530363038303430325a3054310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d49310f300d060355040513063030343031353119301706035504030c1044532d415553545249412d654d525444308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200048893905193f315ee2e2f1eee3fd5a496f6637deb3778cfe7cc2f6c7f0682acc795b0290265a2cb83119343544f2bbfe42974159ac77b113dafbee860c2523c06a382015930820155301d0603551d0e04160414e76eaa567acf6568c660c985717c3c8a50bd024b301f0603551d230418301680142692c7e398abfbe35192d3f26e9a317d1fed53bd301a0603551d1004133011810f32303233303530363038303430325a30160603551d20040f300d300b06092a28000a0102010101303e0603551d1f043730353033a031a02f862d687474703a2f2f7777772e626d692e67762e61742f637363612f63726c2f43534341415553545249412e63726c300e0603551d0f0101ff04040302078030370603551d120430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f30370603551d110430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f301d06076781080101060204123010020100310b1301501302415213024944300a06082a8648ce3d040303036700306402303af7ae31ca6b8fafca6ec51985997f7119fb2e6d20d61b5327d5740109aa310b410bfb44f354e086f207fcab721e69ae023046c68fb7909f994350a2d1c84d1ae5dff8c00de6d86b7891a6cf90ceea09159402e6e2ed3fa548db28d33146319eefda"))

	serial := new(big.Int)
	serial.SetBytes(utils.HexToBytes("6189db18b6ede857"))

	issuerAndSerial, _ := asn1.Marshal(struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}{
		Issuer:       asn1.RawValue{FullBytes: utils.HexToBytes("303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941")},
		SerialNumber: serial,
	})

	certs, err := pool.ByIssuerAndSerial(issuerAndSerial)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 matching cert, got %d", len(certs))
	}
}

// ---------------------------------------------------------------------------
// CombinedCertPool.ByIssuerAndSerial
// ---------------------------------------------------------------------------

func TestCombinedCertPoolByIssuerAndSerial(t *testing.T) {
	t.Parallel()

	pool1 := &GenericCertPool{}
	pool2 := &GenericCertPool{}

	// Add the AT cert to pool2 only
	pool2.Add(utils.HexToBytes("308203df30820366a00302010202086189db18b6ede857300a06082a8648ce3d040303303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941301e170d3233303133313038303430325a170d3333303530363038303430325a3054310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d49310f300d060355040513063030343031353119301706035504030c1044532d415553545249412d654d525444308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200048893905193f315ee2e2f1eee3fd5a496f6637deb3778cfe7cc2f6c7f0682acc795b0290265a2cb83119343544f2bbfe42974159ac77b113dafbee860c2523c06a382015930820155301d0603551d0e04160414e76eaa567acf6568c660c985717c3c8a50bd024b301f0603551d230418301680142692c7e398abfbe35192d3f26e9a317d1fed53bd301a0603551d1004133011810f32303233303530363038303430325a30160603551d20040f300d300b06092a28000a0102010101303e0603551d1f043730353033a031a02f862d687474703a2f2f7777772e626d692e67762e61742f637363612f63726c2f43534341415553545249412e63726c300e0603551d0f0101ff04040302078030370603551d120430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f30370603551d110430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f301d06076781080101060204123010020100310b1301501302415213024944300a06082a8648ce3d040303036700306402303af7ae31ca6b8fafca6ec51985997f7119fb2e6d20d61b5327d5740109aa310b410bfb44f354e086f207fcab721e69ae023046c68fb7909f994350a2d1c84d1ae5dff8c00de6d86b7891a6cf90ceea09159402e6e2ed3fa548db28d33146319eefda"))

	combined := &CombinedCertPool{}
	combined.AddCertPool(pool1)
	combined.AddCertPool(pool2)

	serial := new(big.Int)
	serial.SetBytes(utils.HexToBytes("6189db18b6ede857"))

	issuerAndSerial, _ := asn1.Marshal(struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}{
		Issuer:       asn1.RawValue{FullBytes: utils.HexToBytes("303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941")},
		SerialNumber: serial,
	})

	certs, err := combined.ByIssuerAndSerial(issuerAndSerial)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 matching cert from combined pool, got %d", len(certs))
	}
}

func TestCombinedCertPoolByIssuerAndSerialError(t *testing.T) {
	t.Parallel()

	combined := &CombinedCertPool{}
	combined.AddCertPool(&GenericCertPool{})

	_, err := combined.ByIssuerAndSerial([]byte{0xDE, 0xAD})
	if err == nil {
		t.Fatal("expected error for malformed input propagated through CombinedCertPool")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
