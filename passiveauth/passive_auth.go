package passiveauth

import (
	"fmt"
	"log/slog"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso3166"
)

func PassiveAuth(doc *document.Document, trustedCerts cms.CertPool) (err error) {
	// NB currently assumes that EF.SOD DG hashes have been verified earlier
	//		- this is currently done in reader.readDGs()
	// TODO - this will be problematic if we want to verify passiveAuth on the server using an imported Document

	countryCscaCertPool, err := getCountryCscaCerts(doc, trustedCerts)
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

	// TODO - don't throw error just because of passive-auth.... prefer to read the document and return a status

	return nil
}

// TODO - this means that passive-auth cannot be performed on just the SOD... as DG1 is required
//   - this should be made clear and we should perform an explicit check
//
// OR we could just infer the country from DSC.. and get doc.verify to check mrz-country == sod.dsc.country
//   - this actually fgets quite messy... as we want passive-auth to check hashes
func getAlpha2CountryCode(doc *document.Document) (alpha2 string, err error) {
	// NB use Issuing-State to derive the country-code
	// TODO - what if DG1 is not set?
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
