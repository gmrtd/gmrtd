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

//go:embed master_list/DE_ML_2026-01-08-12-20-54.ml
var de_masterList []byte

/*
* Load the (NL) Master List
* https://www.npkd.nl/index.html
 */

//go:embed master_list/NL_ROOT_CA.cer
var nl_masterListRootCA []byte

//go:embed master_list/NL_ML_2026-03-11.ml
var nl_masterList []byte

//go:embed master_list/IDN_2010_SERIES_CSCA_CERT/2010-12_CSCA.cer
var id_2010series_2010 []byte

//go:embed master_list/IDN_2010_SERIES_CSCA_CERT/2016-01_CSCA.cer
var id_2010series_2016 []byte

//go:embed master_list/IDN_2010_SERIES_CSCA_CERT/2020-10_CSCA.cer
var id_2010series_2020 []byte

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

func GermanMasterList() (*SignedDataCertPool, error) {
	return createCertPoolFromSignedDataFn(de_masterList, de_masterListRootCA)
}

func DutchMasterList() (*SignedDataCertPool, error) {
	return createCertPoolFromSignedDataFn(nl_masterList, nl_masterListRootCA)
}

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
