package cms

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

func parseSingleCert(t *testing.T, der []byte) *Certificate {
	t.Helper()
	certs, err := ParseCertificates(der)
	if err != nil || len(certs) != 1 {
		t.Fatalf("ParseCertificates: certs=%d err=%v", len(certs), err)
	}
	return &certs[0]
}

func TestCertificateInfoLinkCert(t *testing.T) {
	// SG "Singapore Passport CA 5", issued by "Singapore Passport CA 4"
	cert := parseSingleCert(t, fuzzCertBytes)

	info := cert.Info()

	want := CertificateInfo{
		Subject:            "CN=Singapore Passport CA 5, OU=ICA, O=Ministry of Home Affairs, C=SG",
		Issuer:             "CN=Singapore Passport CA 4, OU=ICA, O=Ministry of Home Affairs, C=SG",
		Country:            "SG",
		SerialNumber:       "58ED1EE3",
		KeyType:            "RSA(4096)",
		SignatureAlgorithm: "id-RSASSA-PSS",
		SubjectKeyId:       "84CD5D8A477755058D4EC97E0D4992322BE1C545",
		AuthorityKeyId:     "3A4D8DE8FE2407A702BB9F7A320313098A2D4A8D",
		CA:                 true,
	}
	if info.NotBefore == nil || !info.NotBefore.Equal(time.Date(2020, 12, 14, 3, 22, 46, 0, time.UTC)) {
		t.Errorf("NotBefore = %v", info.NotBefore)
	}
	if info.NotAfter == nil || !info.NotAfter.Equal(time.Date(2032, 4, 10, 16, 0, 0, 0, time.UTC)) {
		t.Errorf("NotAfter = %v", info.NotAfter)
	}
	if len(info.FingerprintSHA256) != 64 {
		t.Errorf("FingerprintSHA256 = %q", info.FingerprintSHA256)
	}

	info.NotBefore, info.NotAfter, info.FingerprintSHA256 = nil, nil, ""
	if info != want {
		t.Errorf("Info() =\n%+v\nwant\n%+v", info, want)
	}

	if !cert.IsLinkCert() {
		t.Errorf("IsLinkCert() = false, want true")
	}
}

func TestCertificateInfoSelfSignedCsca(t *testing.T) {
	// UK "Country Signing Authority" CSCA (self-signed); expired 2026-07-24, so it's no longer in the master lists
	cert := parseSingleCert(t, utils.HexToBytes("308205FA308203E2A0030201020204492EAE16300D06092A864886F70D01010B05003041310B3009060355040613026762310E300C060355040A1305554B4B50413122302006035504031319436F756E747279205369676E696E6720417574686F72697479301E170D3130303332343134303230315A170D3236303732343134333230315A3041310B3009060355040613026762310E300C060355040A1305554B4B50413122302006035504031319436F756E747279205369676E696E6720417574686F7269747930820222300D06092A864886F70D01010105000382020F003082020A0282020100C3583682D60EE9DB5E77F3CD27F02C8657ABA30C70A21EBC33FCAFA8E96B5806A090EF29CDC8A4A286F750C4F237CE89A207D460DED39854CFF2BA8F4E7807C655FE1B60E7459FF7E24DE2806EA6823BA8B3DD0A00C80B3DCB8BAE3C4620D9F5A81E3144E7805C96F147AFB13D6C9BAAB3D469EFCA9EADACAD81ED623FCCA82263D72350F553C17DE29352F937CA3EEFDAA902FE718EFC5F90CE9B35027E5F56CD92FDE396B2ACD2C8A83A7F5712CF7DF298607D072B8E82C5DD94BE323D293ADBD25B4F53467AAAE53E92BDD23E26B5501DA24B53E1F492917CA0FA8C59680FB17C952AC642944639B385A06315C251B204DD922E2F86A1D40F1FE3626E602D8D9ED0870C5D0E86ACB0E3845557E63CBB327D9EFFECD317A31FA337AEAC6F9304EB59B63DFEA4D7EC7AC94891D5D8B14F4FB4DB1AA4A88AD5B339FE7DCB460F8231F5B0628A6EA75C3FC252BF00C0D54D850D489346F3753A476A0EA237CAF9001CE729BB2EC2CEA6368F040A2B1B1108A2133EFFE4CA369D043D58A72D0AC1202138CCA1A370B26D576DA079DBDD6C59989F1E40F670AF27E28231ED3F7A5C7F1F699B9AB217F7125993CDA5C0B25147A0C37D08098B85D8B4F231303B1DF92EFAF03E31D92DE00D6971FD4D43971C318DCCB3F1FE908520F5AA788EADE562D0B23F85FF76340C5D181811B2C19529387807EBDD7C5AB09D971F0D3AB516AD0203010001A381F93081F6300E0603551D0F0101FF04040302010630120603551D130101FF040830060101FF02010030630603551D1F045C305A3058A056A054A4523050310B3009060355040613026762310E300C060355040A1305554B4B50413122302006035504031319436F756E747279205369676E696E6720417574686F72697479310D300B0603550403130443524C31302B0603551D1004243022800F32303130303332343134303230315A810F32303236303732343134333230315A301F0603551D230418301680144531A5B73BCF8BB27C7FAC88C74B4505F6C936B3301D0603551D0E041604144531A5B73BCF8BB27C7FAC88C74B4505F6C936B3300D06092A864886F70D01010B0500038202010054F23F6A723698B06338E7A37FB2C740506E2175970C76E20D629D0AB5557359360826E7A611B3748470C1E7995952547C1BB790F4899D258F9127F6C4730F5FF63A8498EAEB50FAF767283B73325B968B497E8C6361073EC25DA7E4C225F36E5870D5874F11BC102F4DC2FEE784F3B3CB9AF3BD3C55F5A72C1883EB2632153B16F594AA086D549228CF0013199D66899181BE47AC0EF37D5F4FE7CB23B8565CD7F4099968DD90791E8EAAE871914BB25C4ABC5556D8387D4964CD87051088431FC32AAC31E37DCEE14BA835C9618E1365216BD227563D99520FD03B101CA7EABFE326BA71B4DE40DA328B2F65E99B591B01FC132C9713BF525238FEDE68A509653C196AA73404D970509D7112EFBC62F385F9642DDE0FBFC7228E0AB388C69E0304B617CC56E4B6253FBD005B22AFF67420F51069AE8D2DC9E5F076E33016AA4E1BBE11A3B79CBA4E41002021639126B7DDC79DC6DF2CD2C1DDB706B825125514F8E5797C409B1B69A8EADA1E95E1FAD139F7C1E189008A5BAB74DF7E87830AF1FBDFC27BD1985CF8DFE5C631AA4F7C0D439D80FB35B34F7722FC0EFBD2B88B4C4BC918EE4E5BD868EB49E1B6858696B364BCEC7D69E494E7DA8198D69A6ABE1F31D01502F5E78550808C2F14CD447E0E56ACDF01A5A145C52EC867232091F1C71800654CC7529557C3414667F9711275B36E92196DD8D600587D4E93FD08D3"))

	info := cert.Info()
	if !info.CA || info.KeyType != "RSA(4096)" || info.Country != "gb" ||
		info.SubjectKeyId != info.AuthorityKeyId || info.Subject != info.Issuer {
		t.Errorf("unexpected Info(): %+v", info)
	}
	if cert.IsLinkCert() {
		t.Errorf("IsLinkCert() = true, want false")
	}
}

func TestCertificateInfoMalformed(t *testing.T) {
	var cert Certificate

	info := cert.Info()
	want := CertificateInfo{FingerprintSHA256: info.FingerprintSHA256}
	if info != want {
		t.Errorf("Info() = %+v, want only a fingerprint", info)
	}
	if cert.KeyType() != "" {
		t.Errorf("KeyType() = %q, want empty", cert.KeyType())
	}
	if cert.IsLinkCert() {
		t.Errorf("IsLinkCert() = true, want false")
	}
}

func TestAlgorithmName(t *testing.T) {
	testCases := []struct {
		oid  asn1.ObjectIdentifier
		want string
	}{
		{nil, ""},
		{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, "ecdsa-with-SHA384"},
		{asn1.ObjectIdentifier{1, 2, 3, 4}, "1.2.3.4"},
	}
	for _, tc := range testCases {
		if got := algorithmName(tc.oid); got != tc.want {
			t.Errorf("algorithmName(%v) = %q, want %q", tc.oid, got, tc.want)
		}
	}
}

func TestSignerCertificates(t *testing.T) {
	sd, err := ParseSignedData(fuzzSignedDataBytes)
	if err != nil {
		t.Fatalf("ParseSignedData error: %s", err)
	}

	certs, err := sd.SignerCertificates()
	if err != nil {
		t.Fatalf("SignerCertificates error: %s", err)
	}
	if len(certs) != 1 {
		t.Fatalf("SignerCertificates: got %d certs, want 1", len(certs))
	}
	if got := certs[0].Info().Subject; got != "CN=DS-AUSTRIA-eMRTD, SERIALNUMBER=004015, OU=BMI, O=GV, C=AT" {
		t.Errorf("signer subject = %q", got)
	}
}

func TestSignerCertificatesError(t *testing.T) {
	sd := SignedData{SignerInfos: []SignerInfo{{Sid: asn1.RawValue{Tag: 5}}}}

	if _, err := sd.SignerCertificates(); err == nil {
		t.Fatalf("expected error for unselectable signer")
	}
}

func TestCertificateKeyType(t *testing.T) {
	ecSpki := func(params asn1.RawValue) []byte {
		b, _ := asn1.Marshal(SubjectPublicKeyInfo{
			Algorithm:        AlgorithmIdentifier{Algorithm: oid.OidEcPublicKey, Parameters: params},
			SubjectPublicKey: asn1.BitString{Bytes: []byte{0x04, 0x01, 0x02}},
		})
		return b
	}
	namedCurve := func(curve asn1.ObjectIdentifier) asn1.RawValue {
		b, _ := asn1.Marshal(curve)
		return asn1.RawValue{FullBytes: b}
	}
	rsaSpki := func(key []byte) []byte {
		b, _ := asn1.Marshal(SubjectPublicKeyInfo{
			Algorithm:        AlgorithmIdentifier{Algorithm: oid.OidRsaEncryption},
			SubjectPublicKey: asn1.BitString{Bytes: key},
		})
		return b
	}
	rsaKey, _ := asn1.Marshal(struct {
		N *big.Int
		E int
	}{N: new(big.Int).SetBytes(bytes.Repeat([]byte{0xFF}, 64)), E: 65537})
	unknownSpki, _ := asn1.Marshal(SubjectPublicKeyInfo{Algorithm: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}}})

	testCases := []struct {
		name string
		spki []byte
		want string
	}{
		{"invalid SPKI", []byte{0xFF, 0xFF}, ""},
		{"EC named curve", ecSpki(namedCurve(oid.OidPrime256v1)), "EC(P-256)"},
		{"EC unknown curve", ecSpki(namedCurve(oid.OidRsaEncryption)), "EC(?)"},
		{"EC no curve parameters", ecSpki(asn1.RawValue{}), "EC(?)"},
		{"RSA", rsaSpki(rsaKey), "RSA(512)"},
		{"RSA bad key", rsaSpki([]byte{0xFF, 0xFF}), "RSA(?)"},
		{"unknown algorithm", unknownSpki, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cert := Certificate{TbsCertificate: TBSCertificate{SubjectPublicKeyInfo: asn1.RawValue{FullBytes: tc.spki}}}
			if got := cert.KeyType(); got != tc.want {
				t.Errorf("KeyType() = %q, want %q", got, tc.want)
			}
		})
	}
}
