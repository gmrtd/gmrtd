package cms

import (
	_ "embed"
	"fmt"
	"sync"
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

var (
	crlFetcher     *CRLFetcher
	crlFetcherOnce sync.Once
)

// getCRLFetcher returns a singleton CRL fetcher instance
func getCRLFetcher() *CRLFetcher {
	crlFetcherOnce.Do(func() {
		crlFetcher = NewCRLFetcher()
	})
	return crlFetcher
}

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
	certPool, err := CreateCertPoolFromSignedData(de_masterList, de_masterListRootCA)
	if err != nil {
		return nil, err
	}

	// Fetch and set the German CRL
	fetcher := getCRLFetcher()
	crl, err := fetcher.FetchCRL("http://bsi.bund.de/csca_crl")
	if err != nil {
		// Log error but don't fail - CRL is optional
		fmt.Printf("Warning: failed to fetch German CRL: %v\n", err)
	} else {
		certPool.SetCRL(crl)
	}

	return certPool, nil
}

func GetDutchMasterList() (*SignedDataCertPool, error) {
	certPool, err := CreateCertPoolFromSignedData(nl_masterList, nl_masterListRootCA)
	if err != nil {
		return nil, err
	}

	// Fetch and set the Dutch CRL
	fetcher := getCRLFetcher()
	crl, err := fetcher.FetchCRL("http://crl.npkd.nl/crls/NLD.crl")
	if err != nil {
		// Log error but don't fail - CRL is optional
		fmt.Printf("Warning: failed to fetch Dutch CRL: %v\n", err)
	} else {
		certPool.SetCRL(crl)
	}

	return certPool, nil
}
