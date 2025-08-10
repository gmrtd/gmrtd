package passiveauth

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
)

// performs passive-authentication
// SoD is mandatory, CardSecurity is optional
// country will be determined from SoD (certificate) and DG1 will be verified (if present)
// DG hashes will be computed and must match SoD hashes
func PassiveAuth(doc *document.Document, trustedCerts cms.CertPool) (err error) {
	countryCscaCertPool, err := getCountryCscaCerts(doc, trustedCerts)
	if err != nil {
		return fmt.Errorf("[PassiveAuth] error getting country CSCA certs: %w", err)
	}
	if countryCscaCertPool.Count() < 1 {
		return fmt.Errorf("[PassiveAuth] Cannot perform Passive-Auth as unable to locate any CSCA Certificates for the MRZ Country")
	}

	/*
	* verify EF.SOD (mandatory)
	 */
	if doc.Mf.Lds1.Sod == nil {
		return fmt.Errorf("[PassiveAuth] mandatory file EF.SOD is missing")
	} else {
		// validate that any data-groups that are covered by SoD proection have valid hashes
		if err = validateDgHashes(*doc); err != nil {
			return fmt.Errorf("[PassiveAuth] validateDgHashes error: %w", err)
		}

		var certChainSOD [][]byte
		certChainSOD, err = doc.Mf.Lds1.Sod.SD.Verify(countryCscaCertPool)
		if err != nil {
			return fmt.Errorf("[PassiveAuth] unable to verify SignedData (SOD): %w", err)
		}

		doc.PassiveAuthSOD = document.NewPassiveAuth(certChainSOD)

		slog.Debug("PassiveAuth", "certChain(SOD)-cnt", len(certChainSOD))
	}

	/*
	* verify CardSecurity (if present)
	 */
	if doc.Mf.CardSecurity != nil {
		var certChainCardSecurity [][]byte
		certChainCardSecurity, err = doc.Mf.CardSecurity.SD.Verify(countryCscaCertPool)
		if err != nil {
			return fmt.Errorf("[PassiveAuth] unable to verify SignedData (CardSecurity): %w", err)
		}

		doc.PassiveAuthCardSec = document.NewPassiveAuth(certChainCardSecurity)

		slog.Debug("PassiveAuth", "certChain(CardSecurity)-cnt", len(certChainCardSecurity))
	}

	return nil
}

// validates the DG hashes against the hashes in SoD
// will throw error if the document contains a DG that isn't referenced in SoD (e.g. DG injection)
func validateDgHashes(doc document.Document) error {
	// pre-compute the hashes of any applicable DGs in the document
	dgHashes, err := doc.DgHashes()
	if err != nil {
		return fmt.Errorf("[validateDgHashes] DgHashes error : %w", err)
	}

	// for each DG hash from the document, check it matches SoD
	for dgId, dgHash := range dgHashes {
		sodHash := doc.Mf.Lds1.Sod.DgHash(dgId)

		if len(sodHash) <= 0 {
			return fmt.Errorf("[validateDgHashes] DG hash is not present in SoD (dg:%1d)", dgId)
		}

		if !bytes.Equal(dgHash, sodHash) {
			return fmt.Errorf("[validateDgHashes] DG hash mismatch (dg:%1d) (act:%x, exp:%x)", dgId, dgHash, sodHash)
		}
	}

	return nil
}

// determines the country-code for the document (alpha2)
// primarily uses SoD (Certificate country), but also verifies DG1(MRZ) if DG1 is present
func getAlpha2CountryCode(doc *document.Document) (alpha2 string, err error) {
	if doc.Mf.Lds1.Sod == nil {
		return "", fmt.Errorf("[getAlpha2CountryCode] cannot infer country without SoD")
	}

	sodCountryAlpha2, err := doc.Mf.Lds1.Sod.GetCertCountryAlpha2()
	if err != nil {
		return "", fmt.Errorf("[getAlpha2CountryCode] unable to determine country from SoD: %w", err)
	}

	// verify the DG1 has the same country (if present)
	if doc.Mf.Lds1.Dg1 != nil {
		dg1CountryAlpha2, err := doc.Mf.Lds1.Dg1.GetIssuingCountryAlpha2()
		if err != nil {
			return "", fmt.Errorf("[getAlpha2CountryCode] dg1.GetIssuingCountryAlpha2 error: %w", err)
		}

		if !strings.EqualFold(sodCountryAlpha2, dg1CountryAlpha2) {
			return "", fmt.Errorf("[getAlpha2CountryCode] country mismatch between SoD and DG1 (sod:%s, dg1:%s)", sodCountryAlpha2, dg1CountryAlpha2)
		}
	}

	return sodCountryAlpha2, nil
}

// gets the country CSCA certificates based on the document (SOD/DG1)
// NB may return 0 certificates
func getCountryCscaCerts(doc *document.Document, trustedCerts cms.CertPool) (countryCerts *cms.GenericCertPool, err error) {
	countryCode, err := getAlpha2CountryCode(doc)
	if err != nil {
		return nil, fmt.Errorf("(getCountryCscaCerts) unable to get Country-Code from Document: %w", err)
	}

	countryCerts = &cms.GenericCertPool{}
	countryCerts.AddCerts(trustedCerts.GetByIssuerCountry(countryCode))

	slog.Debug("getCountryCscaCerts", "country", countryCode, "cert-cnt", countryCerts.Count())

	return countryCerts, nil
}
