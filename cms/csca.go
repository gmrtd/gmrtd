package cms

import (
	_ "embed"
	"encoding/asn1"
	"log"
	"log/slog"
	"sync"

	"github.com/gmrtd/gmrtd/utils"
)

/*
* Load the (DE) Master List
 */
//go:embed master_list/DE_ML_2024-08-07-07-38-24.ml
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

func CscaCertPool() *CertPool {
	if cscaCertPool == nil {
		lock.Lock()
		defer lock.Unlock()

		cscaCertPool = loadMasterListDE()
	}

	// TODO - should return a copy?
	return cscaCertPool
}

func loadMasterListDE() *CertPool {
	var out *CertPool = NewCertPool()

	var err error

	var signedData *SignedData
	signedData, err = ParseSignedData(masterList)
	if err != nil {
		log.Panicf("error: %s", err)
	}
	// TODO - where do we validate the hash?... currently removed due to missing attributes
	// TODO - should really check we go signedData object? or will CMS do this?
	/*
		var verified bool
		verified, err = signedData.SD2.Verify(NewCertPool())
		if err != nil {
			log.Panicf("error: %s", err)
		}
		if !verified {
			log.Panicf("unable to verify")
		}
	*/

	{
		var certs CscaMasterList

		err := utils.ParseAsn1(signedData.SD2.Content.EContent, false, &certs)
		if err != nil {
			log.Panicf("error: %s", err)
		}

		slog.Debug("loadMasterListDE", "cert-cnt", len(certs.Certs))

		// for each cert in the master list
		for i := 0; i < len(certs.Certs); i++ {
			data := certs.Certs[i].Cert
			out.Add(data)
		}
	}

	return out
}
