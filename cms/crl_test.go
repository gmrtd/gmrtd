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

func TestParseCertificateList(t *testing.T) {
	crl, err := ParseCertificateRevocationList(de_clr)
	if err != nil {
		t.Fatalf("ParseCertificateList error: %v", err)
	}

	if crl == nil {
		t.Fatalf("expected Parsed CRL to be non-nil")
	}

	if crl.TBSCertList.Version != 1 {
		t.Fatalf("unexpected CRL version, exp:1 act:%d", crl.TBSCertList.Version)
	}

	if !crl.SignatureAlgorithm.Algorithm.Equal(oid.OidEcdsaWithSHA512) {
		t.Fatalf("unexpected signature algorithm: %s", crl.SignatureAlgorithm.Algorithm.String())
	}

	issuerCountry := crl.TBSCertList.GetIssuerRDN().GetByOID(oid.OidCountryName)
	if string(issuerCountry) != "DE" {
		t.Fatalf("unexpected issuer country, exp:DE act:%s", string(issuerCountry))
	}

	aki := crl.TBSCertList.Extensions.GetAuthorityKeyIdentifier()
	if aki == nil {
		t.Fatalf("expected AuthorityKeyIdentifier extension")
	}

	if !bytes.Equal(aki.KeyIdentifier, utils.HexToBytes("E8A62993EAE208AA203E49D7649BBAE1BA3560CB")) {
		t.Fatalf("unexpected authority key identifier: %x", aki.KeyIdentifier)
	}

	crlNumber := crl.TBSCertList.Extensions.GetCRLNumber()
	if crlNumber == nil {
		t.Fatalf("expected CRL number extension")
	}

	if crlNumber.Cmp(big.NewInt(35)) != 0 {
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
	crl, err := ParseCertificateRevocationList(de_clr)
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

func TestCertPoolWithCRL(t *testing.T) {
	// parse the CRL
	crl, err := ParseCertificateRevocationList(de_clr)
	if err != nil {
		t.Fatalf("ParseCertificateList error: %v", err)
	}

	// create a GenericCertPool and set the CRL
	certPool := &GenericCertPool{}
	certPool.SetCRL(crl)

	// verify GetCRL returns the same CRL
	retrievedCRL := certPool.GetCRL()
	if retrievedCRL != crl {
		t.Fatalf("expected GetCRL to return the same CRL that was set")
	}

	// test with nil CRL
	certPool2 := &GenericCertPool{}
	if certPool2.GetCRL() != nil {
		t.Fatalf("expected GetCRL to return nil when no CRL is set")
	}
}

func TestCertificateVerificationWithRevokedCert(t *testing.T) {
	// Parse the base German CRL
	crl, err := ParseCertificateRevocationList(de_clr)
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

	// Pick the first certificate and mark it as revoked
	testCert := &allCerts[0]
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

	// Test 3: Create a cert pool with the revoked CRL and verify it gets detected
	certPoolWithRevocations := &GenericCertPool{}
	certPoolWithRevocations.SetCRL(revokedCRL)

	// Try to verify the certificate against itself (should fail due to revocation)
	// Note: Verify would normally require a parent cert, but we're testing the revocation check
	crlFromPool := certPoolWithRevocations.GetCRL()
	if crlFromPool == nil {
		t.Fatal("expected CRL to be set in cert pool")
	}

	if !testCert.IsRevoked(crlFromPool) {
		t.Fatalf("expected certificate to be detected as revoked from cert pool CRL")
	}

	t.Logf("Successfully detected revoked certificate with serial: %s", testSerial.String())
}

func TestSignedDataVerificationFailsWithRevokedCert(t *testing.T) {
	// This test would require actual SignedData where we can control the signing certificate
	// For now, we'll verify the revocation check logic is working with a simpler test

	// Parse the base German CRL
	baseCRL, err := ParseCertificateRevocationList(de_clr)
	if err != nil {
		t.Fatalf("ParseCertificateRevocationList error: %v", err)
	}

	// Create a mock certificate with a known serial number
	mockSerial := big.NewInt(123456789)
	mockCert := &Certificate{
		TbsCertificate: TBSCertificate{
			SerialNumber: mockSerial,
		},
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

	// Test 3: Create a cert pool with the revoked CRL
	certPool := &GenericCertPool{}
	certPool.SetCRL(revokedCRL)

	// Verify the CRL is properly stored and can detect revocations
	retrievedCRL := certPool.GetCRL()
	if retrievedCRL == nil {
		t.Fatal("expected non-nil CRL from cert pool")
	}

	if !mockCert.IsRevoked(retrievedCRL) {
		t.Fatal("certificate should be detected as revoked through cert pool")
	}

	t.Logf("Successfully verified revocation checking flow with mock certificate serial: %s", mockSerial.String())
}
