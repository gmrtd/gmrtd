package cms

import (
	"math/big"
	"testing"
)

func TestCombinedCertPoolWithMixedCRLs(t *testing.T) {
	// Parse the German CRL
	crl, err := ParseCertificateRevocationList(de_clr)
	if err != nil {
		t.Fatalf("ParseCertificateRevocationList error: %v", err)
	}

	// Create first cert pool with CRL
	certPool1 := &GenericCertPool{}
	certPool1.SetCRL(crl)

	// Create second cert pool without CRL
	certPool2 := &GenericCertPool{}

	// Create combined cert pool
	combinedPool := &CombinedCertPool{}
	combinedPool.AddCertPool(certPool1)
	combinedPool.AddCertPool(certPool2)

	// Get CRL from combined pool
	retrievedCRL := combinedPool.GetCRL()

	// Should return the CRL from the first pool
	if retrievedCRL == nil {
		t.Fatal("expected GetCRL to return non-nil CRL from combined pool")
	}

	// Verify it's the same CRL
	if len(retrievedCRL.TBSCertList.RevokedCertificates) != len(crl.TBSCertList.RevokedCertificates) {
		t.Fatalf("expected %d revoked certificates, got %d",
			len(crl.TBSCertList.RevokedCertificates),
			len(retrievedCRL.TBSCertList.RevokedCertificates))
	}
}

func TestCombinedCertPoolWithNoCRLs(t *testing.T) {
	// Create two cert pools without CRLs
	certPool1 := &GenericCertPool{}
	certPool2 := &GenericCertPool{}

	// Create combined cert pool
	combinedPool := &CombinedCertPool{}
	combinedPool.AddCertPool(certPool1)
	combinedPool.AddCertPool(certPool2)

	// Get CRL from combined pool
	retrievedCRL := combinedPool.GetCRL()

	// Should return nil when no pools have CRLs
	if retrievedCRL != nil {
		t.Fatal("expected GetCRL to return nil when no pools have CRLs")
	}
}

func TestCombinedCertPoolWithMultipleCRLs(t *testing.T) {
	// Parse the German CRL
	crl, err := ParseCertificateRevocationList(de_clr)
	if err != nil {
		t.Fatalf("ParseCertificateRevocationList error: %v", err)
	}

	// Create first cert pool with original CRL
	certPool1 := &GenericCertPool{}
	certPool1.SetCRL(crl)

	// Create a second CRL with some revoked certificates
	crl2 := &CertificateList{
		Raw:                crl.Raw,
		TBSCertList:        crl.TBSCertList,
		SignatureAlgorithm: crl.SignatureAlgorithm,
		SignatureValue:     crl.SignatureValue,
	}
	// Add some fake revoked certificates to the second CRL
	crl2.TBSCertList.RevokedCertificates = []RevokedCertificate{
		{UserCertificate: big.NewInt(12345)},
		{UserCertificate: big.NewInt(67890)},
	}

	// Create second cert pool with the modified CRL
	certPool2 := &GenericCertPool{}
	certPool2.SetCRL(crl2)

	// Create combined cert pool
	combinedPool := &CombinedCertPool{}
	combinedPool.AddCertPool(certPool1)
	combinedPool.AddCertPool(certPool2)

	// Get CRL from combined pool
	combinedCRL := combinedPool.GetCRL()

	// Should return a combined CRL
	if combinedCRL == nil {
		t.Fatal("expected GetCRL to return non-nil combined CRL")
	}

	// Verify the combined CRL has all revoked certificates from both CRLs
	expectedCount := len(crl.TBSCertList.RevokedCertificates) + len(crl2.TBSCertList.RevokedCertificates)
	actualCount := len(combinedCRL.TBSCertList.RevokedCertificates)

	if actualCount != expectedCount {
		t.Fatalf("expected %d total revoked certificates in combined CRL, got %d",
			expectedCount, actualCount)
	}

	// Verify that certificates from the second CRL are present
	found12345 := false
	found67890 := false
	for _, revoked := range combinedCRL.TBSCertList.RevokedCertificates {
		if revoked.UserCertificate.Cmp(big.NewInt(12345)) == 0 {
			found12345 = true
		}
		if revoked.UserCertificate.Cmp(big.NewInt(67890)) == 0 {
			found67890 = true
		}
	}

	if !found12345 {
		t.Fatal("expected to find certificate 12345 in combined CRL")
	}
	if !found67890 {
		t.Fatal("expected to find certificate 67890 in combined CRL")
	}
}

func TestCombinedCertPoolCRLOrderDoesNotMatter(t *testing.T) {
	// Parse the German CRL
	crl, err := ParseCertificateRevocationList(de_clr)
	if err != nil {
		t.Fatalf("ParseCertificateRevocationList error: %v", err)
	}

	// Create first cert pool without CRL
	certPool1 := &GenericCertPool{}

	// Create second cert pool with CRL
	certPool2 := &GenericCertPool{}
	certPool2.SetCRL(crl)

	// Create combined cert pool (pool without CRL comes first)
	combinedPool := &CombinedCertPool{}
	combinedPool.AddCertPool(certPool1)
	combinedPool.AddCertPool(certPool2)

	// Get CRL from combined pool
	retrievedCRL := combinedPool.GetCRL()

	// Should still return the CRL even though the pool with CRL is second
	if retrievedCRL == nil {
		t.Fatal("expected GetCRL to return non-nil CRL even when pool with CRL is added second")
	}

	// Verify it's the correct CRL
	if len(retrievedCRL.TBSCertList.RevokedCertificates) != len(crl.TBSCertList.RevokedCertificates) {
		t.Fatalf("expected %d revoked certificates, got %d",
			len(crl.TBSCertList.RevokedCertificates),
			len(retrievedCRL.TBSCertList.RevokedCertificates))
	}
}
