package cms

import (
	_ "embed" // Import for loading master-lists
	"fmt"
)

/*
* Load the (DE) Master List
* https://www.bsi.bund.de/EN/Themen/Oeffentliche-Verwaltung/Elektronische-Identitaeten/Public-Key-Infrastrukturen/CSCA/Root_Cert_Germany/Root_Certificate_node.html
 */

//go:embed master_list/DE_ROOT_CA_CSCA07.cer
var de_masterListRootCA []byte

//go:embed master_list/DE_ML_2025-11-27-07-39-21.ml
var de_masterList []byte

/*
* Load the (NL) Master List
* https://www.npkd.nl/index.html
 */

//go:embed master_list/NL_ROOT_CA.cer
var nl_masterListRootCA []byte

//go:embed master_list/NL_ML_2025-12-20.ml
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
		tmpCertPool, err := GermanMasterList()
		if err != nil {
			return nil, fmt.Errorf("[DefaultMasterList] GermanMasterList error: %w", err)
		}
		out.AddCertPool(tmpCertPool)
	}

	// Dutch
	{
		tmpCertPool, err := DutchMasterList()
		if err != nil {
			return nil, fmt.Errorf("[DefaultMasterList] DutchMasterList error: %w", err)
		}
		out.AddCertPool(tmpCertPool)
	}

	// Indonesia: 2010 CSCA Series Certificate(s)
	// - these are not part of ICAO PKD as Indonesia manages two separate CSCAs (see https://www.imigrasi.go.id/csca)
	{
		tmpCertPool, err := Indonesian2010SeriesCerts()
		if err != nil {
			return nil, fmt.Errorf("[DefaultMasterList] Indonesian2010SeriesCerts error: %w", err)
		}
		out.AddCertPool(tmpCertPool)
	}

	return &out, nil
}

func GermanMasterList() (*SignedDataCertPool, error) {
	return CreateCertPoolFromSignedData(de_masterList, de_masterListRootCA)
}

func DutchMasterList() (*SignedDataCertPool, error) {
	return CreateCertPoolFromSignedData(nl_masterList, nl_masterListRootCA)
}

func Indonesian2010SeriesCerts() (*GenericCertPool, error) {
	// Note: Indonesia manages two seperate CSCAs (2010/2018 series)!
	//
	// Only the 2018 series is published via ICAO PKD (and NL Master-List).
	//
	// As such we need to directly load the 2010 Series (for which there will not
	// be any new CSCA certs issued) based on the certs published at:
	// - https://www.imigrasi.go.id/csca
	var certPool GenericCertPool
	var err error

	if err = certPool.Add(id_2010series_2010); err != nil {
		return nil, fmt.Errorf("[GetIndonesian2010SeriesCerts] Error adding 2010 cert: %w", err)
	}

	if err = certPool.Add(id_2010series_2016); err != nil {
		return nil, fmt.Errorf("[GetIndonesian2010SeriesCerts] Error adding 2016 cert: %w", err)
	}

	if err = certPool.Add(id_2010series_2020); err != nil {
		return nil, fmt.Errorf("[GetIndonesian2010SeriesCerts] Error adding 2020 cert: %w", err)
	}

	return &certPool, nil
}
