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
	pool, err := DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList error: %s", err)
	}

	// UK "Country Signing Authority" CSCA (self-signed)
	ski := utils.HexToBytes("4531A5B73BCF8BB27C7FAC88C74B4505F6C936B3")
	certs := pool.BySKI(ski)
	if len(certs) < 1 {
		t.Fatalf("UK CSCA not found in master list")
	}
	cert := &certs[0]

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
