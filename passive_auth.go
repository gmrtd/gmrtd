package gmrtd

import (
	"fmt"

	"github.com/gmrtd/gmrtd/document"
)

func PassiveAuth(doc *document.Document) error {
	var err error

	// NB currently assumes that EF.SOD DG hashes have been verified earlier
	//		- this is currently done in reader.readDGs()

	/*
	* verify EF.SOD (mandatory)
	 */
	if doc.Mf.Lds1.Sod == nil {
		return fmt.Errorf("mandatory file EF.SOD is missing")
	} else {
		var valid bool

		valid, err = doc.Mf.Lds1.Sod.SD.SD2.Verify()
		if err != nil {
			return fmt.Errorf("unable to verify SignedData (SOD): %w", err)
		}
		if !valid {
			return fmt.Errorf("failed to verify SignedData (SOD): %w", err)
		}
	}

	/*
	* verify CardSecurity (if present)
	 */
	if doc.Mf.CardSecurity != nil {
		var valid bool

		valid, err = doc.Mf.CardSecurity.SD.SD2.Verify()
		if err != nil {
			return fmt.Errorf("unable to verify SignedData (CardSecurity): %w", err)
		}
		if !valid {
			return fmt.Errorf("failed to verify SignedData (CardSecurity): %w", err)
		}
	}

	return nil
}
