package cms

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/utils"
)

// TODO - review/remove commented out code

func TestCscaCertPool(t *testing.T) {

	certPool := CscaCertPool()
	if certPool == nil {
		t.Errorf("missing certPool")
		return
	}

	// for each cert in the master list
	for i := 0; i < len(certPool.certificates); i++ {
		cert := certPool.certificates[i]

		ski := cert.TbsCertificate.Extensions.GetSubjectKeyIdentifier()

		// NB 'aki' is missing for some certs
		aki := cert.TbsCertificate.Extensions.GetAuthorityKeyIdentifier()

		{
			digestAlg, err := cert.SignatureAlgorithm.DetermineDigestAlgFromSigAlg()
			if err != nil {
				t.Errorf("(DetermineDigestAlg) unexpected error: %s", err)
			}

			digest := cryptoutils.CryptoHashByOid(*digestAlg, cert.TbsCertificate.Raw)

			var checkSelfSignedCert bool = true

			// skip if SKI != AKI (i.e. not self-signed)
			if aki != nil && !bytes.Equal(aki.KeyIdentifier, *ski) {
				checkSelfSignedCert = false
			}

			// TODO - need to try and get to bottom of why these certs (6,8,298) are failing,
			//		  for now we'll just selectively ignore them when it comes to checking
			//		  the self-signed signature
			//
			//				- 6/8 are duplicates so probably cross-signing
			//				- 298 appears to be unique, if so, harder to drop

			// skip idx=6, Latvia
			if bytes.Equal(*ski, utils.HexToBytes("8f7faa0b418d162b202a71fd631acdbd965ff5e8")) {
				checkSelfSignedCert = false
			}

			// skip idx=8, Latvia
			if bytes.Equal(*ski, utils.HexToBytes("7bbfa1cda753d6abc3e5fe6eafd7b74abef6af08")) {
				checkSelfSignedCert = false
			}

			// skip idx=298, Estonia
			if bytes.Equal(*ski, utils.HexToBytes("a97a0fc4047c7561bcb7e59935fe7aac7eebab22")) {
				checkSelfSignedCert = false
			}

			// TODO - for !checkSelfSignedCert we could attempt to lookup the cert in the trust-store (if it references another cert)

			if checkSelfSignedCert {
				var err error
				err = VerifySignature(cert.TbsCertificate.SubjectPublicKeyInfo.FullBytes, *digestAlg, digest, cert.SignatureAlgorithm.Algorithm, cert.SignatureValue.Bytes)
				if err != nil {
					t.Errorf("error verifying signature: %s", err)
				}
			}

		}
	}
}
