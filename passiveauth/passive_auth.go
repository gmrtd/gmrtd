package passiveauth

import (
	"fmt"
	"log/slog"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso3166"
)

func PassiveAuth(doc *document.Document) (err error) {
	// NB currently assumes that EF.SOD DG hashes have been verified earlier
	//		- this is currently done in reader.readDGs()
	// TODO - this will be problematic if we want to verify passiveAuth on the server using an imported Document

	countryCscaCertPool, err := getCountryCscaCerts(doc)
	if err != nil {
		return fmt.Errorf("(PassiveAuth) error getting country CSCA certs: %w", err)
	}
	if countryCscaCertPool.Count() < 1 {
		return fmt.Errorf("(PassiveAuth) Cannot perform Passive-Auth as unable to locate any CSCA Certificates for the MRZ Country")
	}

	/*
	* verify EF.SOD (mandatory)
	 */
	if doc.Mf.Lds1.Sod == nil {
		return fmt.Errorf("(PassiveAuth) mandatory file EF.SOD is missing")
	} else {
		var certChainSOD [][]byte
		certChainSOD, err = doc.Mf.Lds1.Sod.SD.Verify(countryCscaCertPool)
		if err != nil {
			return fmt.Errorf("(PassiveAuth) unable to verify SignedData (SOD): %w", err)
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
			return fmt.Errorf("(PassiveAuth) unable to verify SignedData (CardSecurity): %w", err)
		}

		doc.PassiveAuthCardSec = document.NewPassiveAuth(certChainCardSecurity)

		slog.Debug("PassiveAuth", "certChain(CardSecurity)-cnt", len(certChainCardSecurity))
	}

	return nil
}

func getAlpha2CountryCode(doc *document.Document) (alpha2 string, err error) {
	// NB use Issuing-State to derive the country-code
	var mrzCountryAlpha3 string = doc.Mf.Lds1.Dg1.Mrz.IssuingState

	// Note: special handling for Germany, who use 'special' country-code (D) in the MRZ
	//       - refer to ICAO9303p3 (5. CODES FOR NATIONALITY...)
	if mrzCountryAlpha3 == "D" {
		return "DE", nil
	}

	country := iso3166.GetByAlpha3(mrzCountryAlpha3)
	if country == nil {
		return "", fmt.Errorf("(getAlpha2CountryCode) Unable to resolve alpha3 country code (%s)", mrzCountryAlpha3)
	}

	return country.Alpha2, nil
}

// gets the country CSCA certificates based on the MRZ Issuing State
// NB may return 0 certificates
func getCountryCscaCerts(doc *document.Document) (countryCerts *cms.CertPool, err error) {
	countryCode, err := getAlpha2CountryCode(doc)
	if err != nil {
		return nil, fmt.Errorf("(getCountryCscaCerts) unable to get Country-Code from Document: %w", err)
	}

	countryCerts = cms.NewCertPool()

	{
		var cscaCertPool *cms.CertPool

		cscaCertPool, err = cms.CscaCertPool()
		if err != nil {
			return nil, fmt.Errorf("(getCountryCscaCerts) CscaCertPool error: %w", err)
		}

		tmpCountryCerts := cscaCertPool.GetByIssuerCountry(countryCode)

		countryCerts.AddCerts(tmpCountryCerts)
	}

	slog.Info("getCountryCscaCerts", "country", countryCode, "cert-cnt", countryCerts.Count())

	return countryCerts, nil
}
