package cms

import (
	_ "embed"
	"fmt"
)

/*
* Load the (DE) Master List
* https://www.bsi.bund.de/EN/Themen/Oeffentliche-Verwaltung/Elektronische-Identitaeten/Public-Key-Infrastrukturen/CSCA/Root_Cert_Germany/Root_Certificate_node.html
 */

//go:embed master_list/DE_ROOT_CA_CSCA07.cer
var de_masterListRootCA []byte

//go:embed master_list/DE_ML_2025-08-14-07-41-09.ml
var de_masterList []byte

/*
* Load the (NL) Master List
* https://www.npkd.nl/index.html
 */

//go:embed master_list/NL_ROOT_CA.cer
var nl_masterListRootCA []byte

//go:embed master_list/NL_ML_2025-07-29.ml
var nl_masterList []byte

func GetDefaultMasterList() (*CombinedCertPool, error) {
	var out CombinedCertPool

	// German
	{
		tmpCertPool, err := GetGermanMasterList()
		if err != nil {
			return nil, fmt.Errorf("[GetDefaultMasterList] GetGermanMasterList error: %w", err)
		}
		out.AddCertPool(tmpCertPool)
	}

	// Dutch
	{
		tmpCertPool, err := GetDutchMasterList()
		if err != nil {
			return nil, fmt.Errorf("[GetDefaultMasterList] GetDutchMasterList error: %w", err)
		}
		out.AddCertPool(tmpCertPool)
	}

	return &out, nil
}

func GetGermanMasterList() (*SignedDataCertPool, error) {
	return CreateCertPoolFromSignedData(de_masterList, de_masterListRootCA)
}

func GetDutchMasterList() (*SignedDataCertPool, error) {
	return CreateCertPoolFromSignedData(nl_masterList, nl_masterListRootCA)
}
