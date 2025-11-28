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

var nld_clr_hex = "308202fb3081e4020101300d06092a864886f70d01010b05003075310a300806035504051301373110300e06035504030c0743534341204e4c31233021060355040b0c1a4b696e67646f6d206f6620746865204e65746865726c616e647331233021060355040a0c1a4b696e67646f6d206f6620746865204e65746865726c616e6473310b3009060355040613024e4c170d3235303531393039343133395a170d3235313131383030303030305aa03b3039302b0603551d23042430228020f2423ba9c13c6815d65081792bf7307129046f336c2389950b82e998ac3bbca4300a0603551d140403020107300d06092a864886f70d01010b05000382020100cad4bf69e8b50e2c8af2f984b7c0053e77590067280c3b10b33c2e4c63e35dc49f884d525a07aa91141340299e962e09cb1cae10c75477e866ba9af857e2320aa9685bfc6b641aaa0f91144e51c0886c56dc63b7129247ff8908440dc8c3bb1b981664ef1ddbcf514ce2d296f732b5df761c911a6514216d5bbb02bd49bf43a38cf1ff7a63cb5b3fe30723a0f4ca0d777dafbd12dea1c8bdd99e0734e05677278c44baf7183c358740b14948e156cbf5d165e8d327c0544d10baa5b25ec803f4c163cbb53b15de8a85a91fc99830407df69dab7694fa3b9d1f8ec354b395579fcdd2d61221922d19c6ed27ecc12b7e56e896b1c909df82a45e7d36d033d4343c504c0fb311fe231f304be5f643a7d67579f17fb88f045a6f5d5c1a87a8b116ba663a5c2e62e8a924d27ed8e0ae169748a31ac530334d85985d4b0f066cd013616b997cf99c0b62c509a0573a336b5d04d542c2ba6cce5d7c97e599bcb98478bb60bf703138f65578634a20cbc06b4eb0ee1db7df438b3234ae141805eb1fb2a2f0c32037b6d20ceb8c1ed1cb1d99e5977e381ea6295651e75c7cf8802a75b9390324a7ffb4731206bd3209e6c8e10d692001ad3d0d0cb44e4211026f02eee574b736621028b4c1dc7dfd4a1f917050b7d57dca512dfbaaf9440c988c50a70d68ce812abbc53fdc70b00288d9b43a7fe407db3e5d8729d7398ca0187f66d27b35"
var nld_clr = utils.HexToBytes(nld_clr_hex)

func TestParseCertificateList(t *testing.T) {
	crl, err := ParseCertificateRevocationList(nld_clr)
	if err != nil {
		t.Fatalf("ParseCertificateList error: %v", err)
	}

	if crl == nil {
		t.Fatalf("expected Parsed CRL to be non-nil")
	}

	if crl.TBSCertList.Version != 1 {
		t.Fatalf("unexpected CRL version, exp:1 act:%d", crl.TBSCertList.Version)
	}

	if !crl.SignatureAlgorithm.Algorithm.Equal(oid.OidSha256WithRSAEncryption) {
		t.Fatalf("unexpected signature algorithm: %s", crl.SignatureAlgorithm.Algorithm.String())
	}

	issuerCountry := crl.TBSCertList.GetIssuerRDN().GetByOID(oid.OidCountryName)
	if string(issuerCountry) != "NL" {
		t.Fatalf("unexpected issuer country, exp:DE act:%s", string(issuerCountry))
	}

	aki := crl.TBSCertList.Extensions.GetAuthorityKeyIdentifier()
	if aki == nil {
		t.Fatalf("expected AuthorityKeyIdentifier extension")
	}

	if !bytes.Equal(aki.KeyIdentifier, utils.HexToBytes("f2423ba9c13c6815d65081792bf7307129046f336c2389950b82e998ac3bbca4")) {
		t.Fatalf("unexpected authority key identifier: %x", aki.KeyIdentifier)
	}

	crlNumber := crl.TBSCertList.Extensions.GetCRLNumber()
	if crlNumber == nil {
		t.Fatalf("expected CRL number extension")
	}

	if crlNumber.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("unexpected CRL number, exp:35 act:%s", crlNumber.String())
	}

	if len(crl.TBSCertList.RevokedCertificates) != 0 {
		t.Fatalf("unexpected revoked certificate entries, got:%d", len(crl.TBSCertList.RevokedCertificates))
	}

	var thisUpdate time.Time
	if _, err := asn1.Unmarshal(crl.TBSCertList.ThisUpdate.FullBytes, &thisUpdate); err != nil {
		t.Fatalf("failed to decode thisUpdate: %v", err)
	}

	if thisUpdate.Year() != 2025 {
		t.Fatalf("unexpected thisUpdate year, exp:2025 act:%d", thisUpdate.Year())
	}

	var nextUpdate time.Time
	if _, err := asn1.Unmarshal(crl.TBSCertList.NextUpdate.FullBytes, &nextUpdate); err != nil {
		t.Fatalf("failed to decode nextUpdate: %v", err)
	}

	if !nextUpdate.After(thisUpdate) {
		t.Fatalf("expected nextUpdate to be after thisUpdate")
	}
}

func TestCertificateIsRevoked(t *testing.T) {
	// parse the CRL
	crl, err := ParseCertificateRevocationList(nld_clr)
	if err != nil {
		t.Fatalf("ParseCertificateList error: %v", err)
	}

	// create a mock certificate with a serial number that IS in the revoked list
	// (this test assumes the CRL has no revoked certificates currently, so we'll test both scenarios)

	// Test 1: Certificate not in revocation list (should return false)
	certNotRevoked := &Certificate{
		TbsCertificate: TBSCertificate{
			SerialNumber: big.NewInt(999999), // arbitrary serial not in the CRL
		},
	}

	if certNotRevoked.IsRevoked(crl) {
		t.Fatalf("expected certificate to NOT be revoked, but IsRevoked returned true")
	}

	// Test 2: Certificate with nil CRL (should return false)
	if certNotRevoked.IsRevoked(nil) {
		t.Fatalf("expected IsRevoked to return false when CRL is nil")
	}

	// Test 3: If the CRL has revoked certificates, test with actual revoked serial
	if len(crl.TBSCertList.RevokedCertificates) > 0 {
		revokedSerial := crl.TBSCertList.RevokedCertificates[0].UserCertificate
		certRevoked := &Certificate{
			TbsCertificate: TBSCertificate{
				SerialNumber: revokedSerial,
			},
		}

		if !certRevoked.IsRevoked(crl) {
			t.Fatalf("expected certificate with serial %s to be revoked, but IsRevoked returned false", revokedSerial.String())
		}
	}
}

// TestCertPoolWithCRL removed - SetCRL/GetCRL methods no longer exist
// CRL checking is now done via VerifyOptions passed to Verify methods

func TestCertificateVerificationWithRevokedCert(t *testing.T) {
	// Parse the base German CRL
	crl, err := ParseCertificateRevocationList(nld_clr)
	if err != nil {
		t.Fatalf("ParseCertificateRevocationList error: %v", err)
	}

	// Get the German master list to have real certificates
	germanCertPool, err := GetGermanMasterList()
	if err != nil {
		t.Fatalf("GetGermanMasterList error: %v", err)
	}

	// Get all certificates from the pool
	allCerts := germanCertPool.GetAll()
	if len(allCerts) == 0 {
		t.Skip("No certificates in German master list to test with")
	}

	// Get the CRL's Authority Key Identifier to find matching certificates
	crlAKI := crl.TBSCertList.Extensions.GetAuthorityKeyIdentifier()

	// Find a certificate whose AKI matches the CRL's AKI
	// This ensures the certificate and CRL have the same issuer
	var testCert *Certificate
	if crlAKI != nil {
		for i := range allCerts {
			certAKI := allCerts[i].TbsCertificate.Extensions.GetAuthorityKeyIdentifier()
			if certAKI != nil && bytes.Equal(certAKI.KeyIdentifier, crlAKI.KeyIdentifier) {
				testCert = &allCerts[i]
				break
			}
		}
	}

	if testCert == nil {
		t.Skip("No certificate found with matching issuer to the CRL")
	}

	testSerial := testCert.TbsCertificate.SerialNumber

	// Create a modified CRL with this certificate revoked
	revokedCRL := &CertificateList{
		Raw:                crl.Raw,
		TBSCertList:        crl.TBSCertList,
		SignatureAlgorithm: crl.SignatureAlgorithm,
		SignatureValue:     crl.SignatureValue,
	}

	// Add the test certificate to the revoked list
	revokedCRL.TBSCertList.RevokedCertificates = append(
		revokedCRL.TBSCertList.RevokedCertificates,
		RevokedCertificate{
			UserCertificate: testSerial,
			RevocationDate:  crl.TBSCertList.ThisUpdate, // Use the CRL's thisUpdate as revocation date
		},
	)

	// Test 1: Verify the certificate is detected as revoked
	if !testCert.IsRevoked(revokedCRL) {
		t.Fatalf("expected certificate with serial %s to be revoked", testSerial.String())
	}

	// Test 2: Verify certificate is not revoked with original CRL (without revocations)
	if testCert.IsRevoked(crl) {
		t.Fatalf("expected certificate with serial %s NOT to be revoked in original CRL", testSerial.String())
	}

	t.Logf("Successfully detected revoked certificate with serial: %s", testSerial.String())
}

func TestSignedDataVerificationFailsWithRevokedCert(t *testing.T) {
	// This test would require actual SignedData where we can control the signing certificate
	// For now, we'll verify the revocation check logic is working with a simpler test

	// Parse the base German CRL
	baseCRL, err := ParseCertificateRevocationList(nld_clr)
	if err != nil {
		t.Fatalf("ParseCertificateRevocationList error: %v", err)
	}

	// Create a mock certificate with a known serial number and matching issuer
	mockSerial := big.NewInt(123456789)

	// Get the CRL's issuer and AKI to create a matching certificate
	crlAKI := baseCRL.TBSCertList.Extensions.GetAuthorityKeyIdentifier()

	mockCert := &Certificate{
		TbsCertificate: TBSCertificate{
			SerialNumber: mockSerial,
			Issuer:       baseCRL.TBSCertList.Issuer, // Match the CRL issuer
			Extensions:   Extensions{},
		},
	}

	// If CRL has AKI, add matching AKI to the certificate
	if crlAKI != nil {
		// Properly encode the Authority Key Identifier extension
		// The extension value should contain the ASN.1 DER encoding of AuthorityKeyIdentifier
		akiEncoded, err := asn1.Marshal(*crlAKI)
		if err != nil {
			t.Fatalf("Failed to marshal AKI: %v", err)
		}

		mockCert.TbsCertificate.Extensions = append(mockCert.TbsCertificate.Extensions, Extension{
			ObjectId: oid.OidAuthorityKeyIdentifier,
			ExtnValue: asn1.RawValue{
				Bytes:     akiEncoded,
				FullBytes: akiEncoded,
			},
		})
	}

	// Test 1: Certificate should not be revoked initially
	if mockCert.IsRevoked(baseCRL) {
		t.Fatal("mock certificate should not be revoked in base CRL")
	}

	// Create a CRL with this certificate revoked
	revokedCRL := &CertificateList{
		Raw:                baseCRL.Raw,
		TBSCertList:        baseCRL.TBSCertList,
		SignatureAlgorithm: baseCRL.SignatureAlgorithm,
		SignatureValue:     baseCRL.SignatureValue,
	}

	revokedCRL.TBSCertList.RevokedCertificates = []RevokedCertificate{
		{
			UserCertificate: mockSerial,
			RevocationDate:  baseCRL.TBSCertList.ThisUpdate,
		},
	}

	// Test 2: Certificate should now be revoked
	if !mockCert.IsRevoked(revokedCRL) {
		t.Fatalf("mock certificate should be revoked in modified CRL")
	}

	t.Logf("Successfully verified revocation checking flow with mock certificate serial: %s", mockSerial.String())
}
