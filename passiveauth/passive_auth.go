package passiveauth

import (
	"fmt"
	"log/slog"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
)

func PassiveAuth(doc *document.Document) (err error) {
	// NB currently assumes that EF.SOD DG hashes have been verified earlier
	//		- this is currently done in reader.readDGs()
	// TODO - this will be problematic if we want to verify passiveAuth on the server using an imported Document

	// get the CSCA certificate pool
	var cscaCertPool *cms.CertPool

	cscaCertPool, err = cms.CscaCertPool()
	if err != nil {
		return fmt.Errorf("(PassiveAuth) CscaCertPool error: %w", err)
	}

	// TODO - easiest way to restrict based on the issuing country is to filter cscaCertPool based on the MRZ country (with 3->2 translation)
	//			- this way 'Verify' continues to be a generic implementation

	/*
	* verify EF.SOD (mandatory)
	 */
	if doc.Mf.Lds1.Sod == nil {
		return fmt.Errorf("(PassiveAuth) mandatory file EF.SOD is missing")
	} else {
		var certChainSOD [][]byte
		certChainSOD, err = doc.Mf.Lds1.Sod.SD.Verify(cscaCertPool)
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
		certChainCardSecurity, err = doc.Mf.CardSecurity.SD.Verify(cscaCertPool)
		if err != nil {
			return fmt.Errorf("(PassiveAuth) unable to verify SignedData (CardSecurity): %w", err)
		}

		doc.PassiveAuthCardSec = document.NewPassiveAuth(certChainCardSecurity)

		slog.Debug("PassiveAuth", "certChain(CardSecurity)-cnt", len(certChainCardSecurity))
	}

	return nil
}
