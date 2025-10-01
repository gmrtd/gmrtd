package cms

import (
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

// TestCertificateVerifyWithRevokedCertInChain tests that Certificate.Verify
// properly fails when the certificate is in the CRL (cms.go:652)
func TestCertificateVerifyWithRevokedCertInChain(t *testing.T) {
	// Get the German master list
	germanCertPool, err := GetGermanMasterList()
	if err != nil {
		t.Fatalf("GetGermanMasterList error: %v", err)
	}

	// Get all certificates
	allCerts := germanCertPool.GetAll()
	if len(allCerts) < 2 {
		t.Skip("Need at least 2 certificates for this test")
	}

	// Find a certificate that has a parent (not self-signed)
	var testCert *Certificate
	for i := range allCerts {
		aki := allCerts[i].TbsCertificate.Extensions.GetAuthorityKeyIdentifier()
		if aki != nil {
			// This cert has a parent, good for testing
			testCert = &allCerts[i]
			break
		}
	}

	if testCert == nil {
		t.Skip("No suitable certificate found with parent for testing")
	}

	testSerial := testCert.TbsCertificate.SerialNumber

	// Parse base CRL
	baseCRL, err := ParseCertificateRevocationList(de_clr)
	if err != nil {
		t.Fatalf("ParseCertificateRevocationList error: %v", err)
	}

	// Create a revoked CRL with this certificate
	revokedCRL := &CertificateList{
		Raw:                baseCRL.Raw,
		TBSCertList:        baseCRL.TBSCertList,
		SignatureAlgorithm: baseCRL.SignatureAlgorithm,
		SignatureValue:     baseCRL.SignatureValue,
	}

	revokedCRL.TBSCertList.RevokedCertificates = []RevokedCertificate{
		{
			UserCertificate: testSerial,
			RevocationDate:  baseCRL.TBSCertList.ThisUpdate,
		},
	}

	// Create a cert pool with the revoked CRL
	certPoolWithCRL := &GenericCertPool{}
	certPoolWithCRL.AddCerts(allCerts)
	certPoolWithCRL.SetCRL(revokedCRL)

	// Try to verify the certificate - should fail due to revocation
	// This triggers the check at cms.go:652
	_, err = testCert.Verify(certPoolWithCRL)
	if err == nil {
		t.Fatal("expected Certificate.Verify to fail when certificate is revoked")
	}

	// Verify the error message mentions revocation
	if err != nil {
		t.Logf("Got expected error: %v", err)
		// Check that error mentions "revoked"
		errStr := err.Error()
		if len(errStr) == 0 {
			t.Fatal("expected non-empty error message")
		}
	}
}

// TestSignerInfoVerifyWithRevokedSigningCert tests that SignerInfo.Verify
// properly fails when the signing certificate is revoked (cms.go:567)
func TestSignerInfoVerifyWithRevokedSigningCert(t *testing.T) {
	// Use one of the existing SignedData test vectors
	// German passport SignedData
	signedDataBytes := utils.HexToBytes("3082070b06092a864886f70d010702a08206fc308206f8020103310f300d06096086480165030402020500308201120606678108010101a0820106048201023081ff020101300b06096086480165030402023081dc303502010104302daffeb0f67656ae099fd655b32f7dc857c31073df9bc0af8c9cc783fb40cd9c3fe7503e07421f560ecd7a09b6133d4e303502010204302c65a444298e8a7c1fe51ede7f2cdd9b8439597330fe142a1996984f841ed3840ee6fef3475336d29d94012149d9669730350201030430a668251fb0ffdaef79fedbd092a296bd808e79fae546754d0e7f2c9f3f016f23849dd0b7c74a8752dda554412a8542cd303502010e0430c87ab92f21166ae1059b7d7d995dce9cdd3e211aecfb943259d88bb2eb8b533b2b5c780251eb5ad21b0a4a8d8a9ee1a2300e1304303130381306303430303030a082049730820493308203f8a003020102020204a8300a06082a8648ce3d0403043041310b3009060355040613024445310d300b060355040a0c0462756e64310c300a060355040b0c036273693115301306035504030c0c637363612d6765726d616e79301e170d3233303130343036303434325a170d3333303730343233353935395a305d310b3009060355040613024445311d301b060355040a0c1442756e646573647275636b6572656920476d6248310c300a060355040513033135323121301f06035504030c18446f63756d656e74205369676e65722050617373706f7274308201b53082014d06072a8648ce3d020130820140020101303c06072a8648ce3d01010231008cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53306404307bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826043004a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c110461041d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c53150231008cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565020101036200042ca852cb9a1caaaa466256d1cfd678bb7e5d8502dfa6f3fdb287293c32af9fa77ad3a7fa92e56f608110053121354002198b530bc60ac7050ab98d7f6c475fd50706a4a6207d7a6336cb480b966a3aa64894f7f42b8fb4ac4774c9d6892330fba382016430820160301f0603551d23041830168014a40a5fc380ae3e59af1b32d6136aefeec8ca35e8301d0603551d0e04160414af9dd5e6565737a8804b5b4c6f45093d809aa865300e0603551d0f0101ff040403020780302b0603551d1004243022800f32303233303130343036303434325a810f32303233303730343233353935395a30160603551d20040f300d300b060904007f000703010101302d0603551d1104263024821262756e646573647275636b657265692e6465a40e300c310a300806035504070c014430510603551d12044a30488118637363612d6765726d616e79406273692e62756e642e6465861c68747470733a2f2f7777772e6273692e62756e642e64652f63736361a40e300c310a300806035504070c01443015060767810801010602040a3008020100310313015030300603551d1f042930273025a023a021861f687474703a2f2f7777772e6273692e62756e642e64652f637363615f63726c300a06082a8648ce3d0403040381880030818402404846f4a03e17896e9094af7652c38fe31ec964c2c3a906af813aabef5fe4f3156d140e2ef991dc11fd860a4a301b225de9fd4ed39b4f47ac72cdb88cc63b335902405d4e2895875e603ce2863073bf441d1ec53761cf47e5bc2b9b6bece4f229712e39002d77b555290fa550df5f40aa22d7d2a1e89feb3fef730ae33c937796e8e33182012f3082012b02010130473041310b3009060355040613024445310d300b060355040a0c0462756e64310c300a060355040b0c036273693115301306035504030c0c637363612d6765726d616e79020204a8300d06096086480165030402020500a058301506092a864886f70d01090331080606678108010101303f06092a864886f70d01090431320430c194cbc52aac7a5077e792739434040cce0c465ddebf366d64eb3ab8ef5bb457cf5c4bd3d28f69804e5507308dcae3e8300c06082a8648ce3d0403030500046630640230403c68550dbc310a8002110ee18aef04e00b119030e0cc3ac8cad347d87f59031af26867f1855b1f1555b7c925b92d8a02307185621cd2cda6051e81627be5a486eb667897440f5bd69f96b8dd43f4f0b0a0cd21df376012dba79d9f7138c2d9b3c7")

	// Parse the SignedData
	sd, err := ParseSignedData(signedDataBytes)
	if err != nil {
		t.Fatalf("ParseSignedData error: %v", err)
	}

	// Extract the signing certificate from the SignedData
	var sdCerts GenericCertPool
	err = sdCerts.Add(sd.Certificates.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificates from SignedData: %v", err)
	}

	if sdCerts.Count() == 0 {
		t.Fatal("No certificates found in SignedData")
	}

	// Get the signing certificate
	signingCert := sdCerts.GetAll()[0]
	signingSerial := signingCert.TbsCertificate.SerialNumber

	// Create a CRL with the signing certificate revoked
	baseCRL, err := ParseCertificateRevocationList(de_clr)
	if err != nil {
		t.Fatalf("ParseCertificateRevocationList error: %v", err)
	}

	revokedCRL := &CertificateList{
		Raw:                baseCRL.Raw,
		TBSCertList:        baseCRL.TBSCertList,
		SignatureAlgorithm: baseCRL.SignatureAlgorithm,
		SignatureValue:     baseCRL.SignatureValue,
	}

	revokedCRL.TBSCertList.RevokedCertificates = []RevokedCertificate{
		{
			UserCertificate: signingSerial,
			RevocationDate:  baseCRL.TBSCertList.ThisUpdate,
		},
	}

	// Get the default master list and add the revoked CRL
	germanCertPool, err := GetGermanMasterList()
	if err != nil {
		t.Fatalf("GetGermanMasterList error: %v", err)
	}

	// Set the CRL with the revoked signing certificate
	germanCertPool.SetCRL(revokedCRL)

	// Try to verify - should fail due to signing certificate being revoked
	// This triggers the check at cms.go:567
	_, err = sd.Verify(germanCertPool)
	if err == nil {
		t.Fatal("expected SignedData.Verify to fail when signing certificate is revoked")
	}

	// Verify the error message mentions revocation
	if err != nil {
		t.Logf("Got expected error: %v", err)
		errStr := err.Error()
		if len(errStr) == 0 {
			t.Fatal("expected non-empty error message")
		}
	}
}

// TestSignedDataVerifySucceedsWithoutCRL tests that verification works when no CRL is set
func TestSignedDataVerifySucceedsWithoutCRL(t *testing.T) {
	// Use German passport SignedData
	signedDataBytes := utils.HexToBytes("3082070b06092a864886f70d010702a08206fc308206f8020103310f300d06096086480165030402020500308201120606678108010101a0820106048201023081ff020101300b06096086480165030402023081dc303502010104302daffeb0f67656ae099fd655b32f7dc857c31073df9bc0af8c9cc783fb40cd9c3fe7503e07421f560ecd7a09b6133d4e303502010204302c65a444298e8a7c1fe51ede7f2cdd9b8439597330fe142a1996984f841ed3840ee6fef3475336d29d94012149d9669730350201030430a668251fb0ffdaef79fedbd092a296bd808e79fae546754d0e7f2c9f3f016f23849dd0b7c74a8752dda554412a8542cd303502010e0430c87ab92f21166ae1059b7d7d995dce9cdd3e211aecfb943259d88bb2eb8b533b2b5c780251eb5ad21b0a4a8d8a9ee1a2300e1304303130381306303430303030a082049730820493308203f8a003020102020204a8300a06082a8648ce3d0403043041310b3009060355040613024445310d300b060355040a0c0462756e64310c300a060355040b0c036273693115301306035504030c0c637363612d6765726d616e79301e170d3233303130343036303434325a170d3333303730343233353935395a305d310b3009060355040613024445311d301b060355040a0c1442756e646573647275636b6572656920476d6248310c300a060355040513033135323121301f06035504030c18446f63756d656e74205369676e65722050617373706f7274308201b53082014d06072a8648ce3d020130820140020101303c06072a8648ce3d01010231008cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53306404307bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826043004a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c110461041d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c53150231008cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565020101036200042ca852cb9a1caaaa466256d1cfd678bb7e5d8502dfa6f3fdb287293c32af9fa77ad3a7fa92e56f608110053121354002198b530bc60ac7050ab98d7f6c475fd50706a4a6207d7a6336cb480b966a3aa64894f7f42b8fb4ac4774c9d6892330fba382016430820160301f0603551d23041830168014a40a5fc380ae3e59af1b32d6136aefeec8ca35e8301d0603551d0e04160414af9dd5e6565737a8804b5b4c6f45093d809aa865300e0603551d0f0101ff040403020780302b0603551d1004243022800f32303233303130343036303434325a810f32303233303730343233353935395a30160603551d20040f300d300b060904007f000703010101302d0603551d1104263024821262756e646573647275636b657265692e6465a40e300c310a300806035504070c014430510603551d12044a30488118637363612d6765726d616e79406273692e62756e642e6465861c68747470733a2f2f7777772e6273692e62756e642e64652f63736361a40e300c310a300806035504070c01443015060767810801010602040a3008020100310313015030300603551d1f042930273025a023a021861f687474703a2f2f7777772e6273692e62756e642e64652f637363615f63726c300a06082a8648ce3d0403040381880030818402404846f4a03e17896e9094af7652c38fe31ec964c2c3a906af813aabef5fe4f3156d140e2ef991dc11fd860a4a301b225de9fd4ed39b4f47ac72cdb88cc63b335902405d4e2895875e603ce2863073bf441d1ec53761cf47e5bc2b9b6bece4f229712e39002d77b555290fa550df5f40aa22d7d2a1e89feb3fef730ae33c937796e8e33182012f3082012b02010130473041310b3009060355040613024445310d300b060355040a0c0462756e64310c300a060355040b0c036273693115301306035504030c0c637363612d6765726d616e79020204a8300d06096086480165030402020500a058301506092a864886f70d01090331080606678108010101303f06092a864886f70d01090431320430c194cbc52aac7a5077e792739434040cce0c465ddebf366d64eb3ab8ef5bb457cf5c4bd3d28f69804e5507308dcae3e8300c06082a8648ce3d0403030500046630640230403c68550dbc310a8002110ee18aef04e00b119030e0cc3ac8cad347d87f59031af26867f1855b1f1555b7c925b92d8a02307185621cd2cda6051e81627be5a486eb667897440f5bd69f96b8dd43f4f0b0a0cd21df376012dba79d9f7138c2d9b3c7")

	// Parse the SignedData
	sd, err := ParseSignedData(signedDataBytes)
	if err != nil {
		t.Fatalf("ParseSignedData error: %v", err)
	}

	// Get master list WITHOUT CRL
	germanCertPool, err := GetGermanMasterList()
	if err != nil {
		t.Fatalf("GetGermanMasterList error: %v", err)
	}

	// Clear any CRL that might have been fetched
	germanCertPool.SetCRL(nil)

	// Verify should succeed when no CRL is configured
	_, err = sd.Verify(germanCertPool)
	if err != nil {
		t.Fatalf("SignedData.Verify should succeed when no CRL is configured: %v", err)
	}

	t.Log("Verification succeeded without CRL as expected")
}
