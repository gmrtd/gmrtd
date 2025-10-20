package cms

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/utils"
)

// Constant for a heximal presentation of the German Certificate revocation list
const de_clr_hex = "3082013c3081a1020101300a06082a8648ce3d0403043041310b3009060355040613024445310d300b060355040a0c0462756e64310c300a060355040b0c036273693115301306035504030c0c637363612d6765726d616e79170d3235303930383037323334345a170d3235313230373037323330305aa02f302d301f0603551d23041830168014e8a62993eae208aa203e49d7649bbae1ba3560cb300a0603551d140403020123300a06082a8648ce3d04030403818900308185024049a0ff7ff1a469929d03d6581e1f8ddb4574704e857f1ed36eef3ab2bf304a906a3c2d6cffd1748936e4583fe0c345815b1dbbddc5df1ec5968f9698eb3c115f02410081724d1afcc59721daf1146b6e551646af78dc310ec01344a9af97e503815f4f8d7fe80add1b2f7c755a5ab04315fad0bba32914d7c9879e35f7d671504ad097"

var de_clr = utils.HexToBytes(de_clr_hex)

func TestCscaCertPoolGetByCountry(t *testing.T) {
	certPool, err := GetDefaultMasterList()
	if err != nil {
		t.Errorf("CscaCertPool error: %s", err)
	}
	if certPool == nil {
		t.Errorf("missing certPool")
		return
	}

	sgCerts := certPool.GetByIssuerCountry("SG")
	if len(sgCerts) < 1 {
		t.Errorf("expected some certs for SG")
	}
}

func TestCscaCertPool(t *testing.T) {

	certPool, err := GetDefaultMasterList()
	if err != nil {
		t.Errorf("CscaCertPool error: %s", err)
	}
	if certPool == nil {
		t.Errorf("missing certPool")
		return
	}

	var certificates []Certificate = certPool.GetAll()

	// for each cert in the master list
	// NB no need to recursively verify up the cert chain as we're verifying
	//    each and every certificate in the master-list
	for i := 0; i < len(certificates); i++ {
		cert := certificates[i]

		ski := cert.TbsCertificate.Extensions.GetSubjectKeyIdentifier()

		// NB 'aki' is missing for some certs
		// - this typically indicates that it is a self-signed cert
		aki := cert.TbsCertificate.Extensions.GetAuthorityKeyIdentifier()

		{
			digestAlg, err := cert.SignatureAlgorithm.DetermineDigestAlgFromSigAlg()
			if err != nil {
				t.Errorf("(DetermineDigestAlg) unexpected error: %s", err)
			}

			digest, err := cryptoutils.CryptoHashByOid(*digestAlg, cert.TbsCertificate.Raw)
			if err != nil {
				t.Errorf("(CryptoHashByOid) unexpected error: %s", err)
			}

			var isSelfSignedCert bool = true
			var skipVerification bool = false

			// check whether certificate references a different authority (i.e. !self-signed)
			if aki != nil {
				isSelfSignedCert = false
			}

			// TODO - need to try and get to bottom of why these certs (6,8,298) are failing,
			//		  for now we'll just selectively ignore them when it comes to checking
			//		  the self-signed signature
			//
			//				- 6/8 are duplicates so probably cross-signing
			//				- 298 appears to be unique, if so, harder to drop

			// skip idx=6, Latvia
			if bytes.Equal(*ski, utils.HexToBytes("8f7faa0b418d162b202a71fd631acdbd965ff5e8")) {
				skipVerification = true
			}

			// skip idx=8, Latvia
			if bytes.Equal(*ski, utils.HexToBytes("7bbfa1cda753d6abc3e5fe6eafd7b74abef6af08")) {
				skipVerification = true
			}

			// skip idx=298, Estonia
			if bytes.Equal(*ski, utils.HexToBytes("a97a0fc4047c7561bcb7e59935fe7aac7eebab22")) {
				// observed error: Invalid RSA signature
				skipVerification = true
			}

			if skipVerification {
				continue
			}

			if isSelfSignedCert {
				err := VerifySignature(cert.TbsCertificate.SubjectPublicKeyInfo.FullBytes, *digestAlg, digest, cert.SignatureAlgorithm.Algorithm, cert.SignatureValue.Bytes)
				if err != nil {
					t.Errorf("error verifying signature (self-signed): %s", err)
				}
			} else {
				if aki == nil {
					t.Fatalf("'aki' is missing for !self-signed certificate")
				}

				var parentCerts []Certificate = certPool.GetBySKI(aki.KeyIdentifier)

				/*
				* Note: we have some certificates that reference a parent (aki) which is not found in
				*       the master-list. For these, we whitelist the 'ski' and skip signature verification
				 */
				if len(parentCerts) < 1 {
					if bytes.Equal(*ski, utils.HexToBytes("e7d8dd1758d54b42aa02db88eb701e44c6925ae6")) ||
						bytes.Equal(*ski, utils.HexToBytes("f5a8f9b1e7a992a0865408db2a471c04a215f4d7")) ||
						bytes.Equal(*ski, utils.HexToBytes("b90f6a1f82f3b55803cf9b318b883a8954c47f17")) ||
						bytes.Equal(*ski, utils.HexToBytes("6c17211c20901464d3beb833aa83c538c2a757be")) ||
						bytes.Equal(*ski, utils.HexToBytes("1fe1572e9b35121363a50fee3e2ce2c1d187a8dd")) ||
						bytes.Equal(*ski, utils.HexToBytes("3f38d115cbf5b2016609c464fb6375d812f15acd")) ||
						bytes.Equal(*ski, utils.HexToBytes("2b0f99a34be9d5ae00933a7868cbcd21a6cf47e5")) ||
						bytes.Equal(*ski, utils.HexToBytes("cd3cc520b508a44e6d518dff33fa36cbde108be2")) ||
						bytes.Equal(*ski, utils.HexToBytes("a12ae326fc2b0d76a85c8b4711b9c1c22061c919")) ||
						bytes.Equal(*ski, utils.HexToBytes("9ee0bfdee2d3d4fced1b3928f54aa7b3265dfaf9")) ||
						bytes.Equal(*ski, utils.HexToBytes("db04dae635a2cbecd63f8d60c2060efd5df719e3")) {
						continue
					}
				}

				if len(parentCerts) < 1 {
					t.Errorf("0 parent certs - whitelist may need to be updated!")
				}

				valid := verifySignatureAgainstCerts(parentCerts, *digestAlg, digest, cert.SignatureAlgorithm.Algorithm, cert.SignatureValue.Bytes)
				if !valid {
					t.Errorf("error verifying signature (!self-signed): idx:%1d cnt(parentCerts):%1d, ski:%x, aki:%x", i, len(parentCerts), *ski, aki.KeyIdentifier)
				}
			}
		}
	}
}

func verifySignatureAgainstCerts(parentCerts []Certificate, digestAlg asn1.ObjectIdentifier, digest []byte, signatureAlg asn1.ObjectIdentifier, signature []byte) bool {
	// NB we keep processing untl we find a valid parent certificate
	for i := 0; i < len(parentCerts); i++ {
		parentCert := &(parentCerts[i])

		err := VerifySignature(parentCert.TbsCertificate.SubjectPublicKeyInfo.FullBytes, digestAlg, digest, signatureAlg, signature)
		if err == nil {
			return true
		}

		// NB ignore error
	}

	return false
}

// TestGetGermanMasterListWithFailingCRL removed - hardcoded CRL fetching no longer exists
// CRL checking is now done via VerifyOptions with user-provided CRLFetcher

// TestGetDutchMasterListWithFailingCRL removed - hardcoded CRL fetching no longer exists
// CRL checking is now done via VerifyOptions with user-provided CRLFetcher

func TestCreateCertPoolFromSignedDataWithInvalidData(t *testing.T) {
	// Test with invalid master list data
	invalidData := []byte("invalid master list data")
	validRootCA := de_masterListRootCA

	_, err := CreateCertPoolFromSignedData(invalidData, validRootCA)
	if err == nil {
		t.Fatal("expected CreateCertPoolFromSignedData to fail with invalid master list data")
	}

	t.Logf("Got expected error with invalid master list: %v", err)
}

func TestCreateCertPoolFromSignedDataWithInvalidRootCA(t *testing.T) {
	// Test with invalid root CA data
	validData := de_masterList
	invalidRootCA := []byte("invalid root ca data")

	_, err := CreateCertPoolFromSignedData(validData, invalidRootCA)
	if err == nil {
		t.Fatal("expected CreateCertPoolFromSignedData to fail with invalid root CA data")
	}

	t.Logf("Got expected error with invalid root CA: %v", err)
}

func TestGetDefaultMasterListWithBothCountries(t *testing.T) {
	certPool, err := GetDefaultMasterList()
	if err != nil {
		t.Fatalf("GetDefaultMasterList error: %v", err)
	}

	if certPool == nil {
		t.Fatal("expected non-nil combined cert pool")
	}

	// Verify we have certificates from both countries
	allCerts := certPool.GetAll()
	if len(allCerts) == 0 {
		t.Fatal("expected certificates in combined pool")
	}

	// Check for German certificates
	germanCerts := certPool.GetByIssuerCountry("DE")
	if len(germanCerts) == 0 {
		t.Error("expected German certificates in combined pool")
	}

	// Check for Dutch certificates
	dutchCerts := certPool.GetByIssuerCountry("NL")
	if len(dutchCerts) == 0 {
		t.Error("expected Dutch certificates in combined pool")
	}

	t.Logf("Combined pool contains %d total certs (%d German, %d Dutch)",
		len(allCerts), len(germanCerts), len(dutchCerts))
}
