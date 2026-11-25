package cms

import (
	_ "embed" // Import for loading master-lists
	"fmt"
)

var (
	createCertPoolFromSignedDataFn = CreateCertPoolFromSignedData

	germanMasterListFn          = GermanMasterList
	dutchMasterListFn           = DutchMasterList
	indonesian2010SeriesCertsFn = Indonesian2010SeriesCerts
)

/*
* Load the (DE) Master List
* https://www.bsi.bund.de/EN/Themen/Oeffentliche-Verwaltung/Elektronische-Identitaeten/Public-Key-Infrastrukturen/CSCA/Root_Cert_Germany/Root_Certificate_node.html
 */

//go:embed master_list/DE_ROOT_CA_CSCA07.cer
var de_masterListRootCA []byte

//go:embed master_list/DE_ML_2026-10-01-11-50-52.ml
var de_masterList []byte

/*
* Load the (NL) Master List
* https://www.npkd.nl/index.html
 */

//go:embed master_list/NL_ROOT_CA.cer
var nl_masterListRootCA []byte

//go:embed master_list/NL_ML_2026-11-09.ml
var nl_masterList []byte

//go:embed master_list/IDN_2010_SERIES_CSCA_CERT/2010-12_CSCA.cer
var id_2010series_2010 []byte

//go:embed master_list/IDN_2010_SERIES_CSCA_CERT/2016-01_CSCA.cer
var id_2010series_2016 []byte

//go:embed master_list/IDN_2010_SERIES_CSCA_CERT/2020-10_CSCA.cer
var id_2010series_2020 []byte

// DefaultMasterList returns a CombinedCertPool of the CSCA certificates embedded in this
// package: the German and Dutch master lists (each verified against its embedded root
// certificate when loaded) and the Indonesian 2010-series CSCA certificates.
func DefaultMasterList() (*CombinedCertPool, error) {
	var out CombinedCertPool

	// German
	{
		tmpCertPool, err := germanMasterListFn()
		if err != nil {
			return nil, fmt.Errorf("[DefaultMasterList] germanMasterListFn error: %w", err)
		}
		out.AddCertPool(tmpCertPool)
	}

	// Dutch
	{
		tmpCertPool, err := dutchMasterListFn()
		if err != nil {
			return nil, fmt.Errorf("[DefaultMasterList] dutchMasterListFn error: %w", err)
		}
		out.AddCertPool(tmpCertPool)
	}

	// Indonesia: 2010 CSCA Series Certificate(s)
	// - these are not part of ICAO PKD as Indonesia manages two separate CSCAs (see https://www.imigrasi.go.id/csca)
	{
		tmpCertPool, err := indonesian2010SeriesCertsFn()
		if err != nil {
			return nil, fmt.Errorf("[DefaultMasterList] indonesian2010SeriesCertsFn error: %w", err)
		}
		out.AddCertPool(tmpCertPool)
	}

	return &out, nil
}

// GermanMasterList loads the embedded German (BSI) CSCA master list, verifying its
// SignedData against the embedded German master-list root certificate.
func GermanMasterList() (*SignedDataCertPool, error) {
	return createCertPoolFromSignedDataFn(de_masterList, de_masterListRootCA)
}

// DutchMasterList loads the embedded Dutch (NPKD) CSCA master list, verifying its
// SignedData against the embedded Dutch master-list root certificate.
func DutchMasterList() (*SignedDataCertPool, error) {
	return createCertPoolFromSignedDataFn(nl_masterList, nl_masterListRootCA)
}

// Indonesian2010SeriesCerts returns a pool of the embedded Indonesian 2010-series CSCA
// certificates, which are not published via the ICAO PKD. The certificates are only parsed,
// not verified.
func Indonesian2010SeriesCerts() (*GenericCertPool, error) {
	return genericCertPoolFromCerts(
		[][]byte{
			id_2010series_2010,
			id_2010series_2016,
			id_2010series_2020,
		},
	)
}

func genericCertPoolFromCerts(certs [][]byte) (*GenericCertPool, error) {
	var certPool GenericCertPool

	for i, cert := range certs {
		if err := certPool.Add(cert); err != nil {
			return nil, fmt.Errorf("[genericCertPoolFromCerts] certPool.Add(i:%d) error: %w", i, err)
		}
	}

	return &certPool, nil
}
