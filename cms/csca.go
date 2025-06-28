package cms

import (
	_ "embed"
	"encoding/asn1"
	"fmt"
	"log"
	"log/slog"
	"sync"

	"github.com/gmrtd/gmrtd/utils"
)

/*
* Load the (DE) Master List Root
 */
//go:embed master_list/DE_ROOT_CA_CSCA07.cer
var masterListRootCA []byte

/*
* Load the (DE) Master List
 */
//go:embed master_list/DE_ML_2025-06-25-09-31-57.ml
// DE_ML_2025-03-05-08-05-28.ml
var masterList []byte

type CscaMasterList struct {
	Version int
	Certs   []CscaMasterListCert `asn1:"set"`
}

type CscaMasterListCert struct {
	Cert asn1.RawContent
}

/*
* shared instance
 */
var lock = &sync.Mutex{}
var cscaCertPool *CertPool

func CscaCertPool() (*CertPool, error) {
	if cscaCertPool == nil {
		lock.Lock()
		defer lock.Unlock()

		var err error

		cscaCertPool, err = loadMasterListDE()
		if err != nil {
			return nil, fmt.Errorf("(CscaCertPool) loadMasterListDE error: %w", err)
		}
	}

	return cscaCertPool, nil
}

// returns: CertPool OR error
func loadMasterListDE() (*CertPool, error) {
	var err error
	var out *CertPool = NewCertPool()

	var signedData *SignedData
	signedData, err = ParseSignedData(masterList)
	if err != nil {
		return nil, fmt.Errorf("(loadMasterListDE) ParseSignedData error: %w", err)
	}

	rootCertPool := NewCertPool()
	err = rootCertPool.Add(masterListRootCA)
	if err != nil {
		return nil, fmt.Errorf("(csca.loadMasterListDE) rootCertPool .add error: %w", err)
	}

	/*
	 * verify the signed data object
	 */
	var certChain [][]byte
	certChain, err = signedData.Verify(rootCertPool)
	if err != nil {
		log.Panicf("error: %s", err)
	}
	if len(certChain) < 1 {
		log.Panicf("empty cert chain")
	}

	{
		var certs CscaMasterList

		err := utils.ParseAsn1(signedData.Content.EContent, false, &certs)
		if err != nil {
			return nil, fmt.Errorf("(loadMasterListDE) ParseAsn1 error: %w", err)
		}

		slog.Debug("loadMasterListDE", "cert-cnt", len(certs.Certs))

		// for each cert in the master list
		for i := 0; i < len(certs.Certs); i++ {
			data := certs.Certs[i].Cert
			err = out.Add(data)
			if err != nil {
				return nil, fmt.Errorf("(csca.loadMasterListDE) masterList .add error: %w", err)
			}
		}
	}

	return out, nil
}
