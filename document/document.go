// Package document implements data structures for representing the content of the MRTD.
package document

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/gmrtd/gmrtd/iso7816"
)

type MasterFile struct {
	CardAccess   *CardAccess
	CardSecurity *CardSecurity // NB only read for PACE-CAM - read during PACE flow
	Dir          *EFDIR        // indicates which applications are present - generally not acvailable
	Lds1         LDS1
}

type LDS1 struct {
	Com  *COM  // largely deprecated by SOD, but used to determine Lds/Unicode Version if older SOD formatis present
	Sod  *SOD  // Document Security Object EF.SOD (MANDATORY)
	Dg1  *DG1  // DATA GROUP 1 — Machine Readable Zone Information (MANDATORY)
	Dg2  *DG2  // DATA GROUP 2 — Encoded Identification Features — Face (MANDATORY)
	Dg7  *DG7  // DATA GROUP 7 — Displayed Signature or Usual Mark (OPTIONAL)
	Dg11 *DG11 // DATA GROUP 11 — Additional Personal Detail(s) (OPTIONAL)
	Dg12 *DG12 // DATA GROUP 12 — Additional Document Detail(s) (OPTIONAL)
	Dg13 *DG13 // DATA GROUP 13 — Optional Details(s) (OPTIONAL)
	Dg14 *DG14 // DATA GROUP 14 — Security Options (CONDITIONAL)
	Dg15 *DG15 // DATA GROUP 15 — Active Authentication Public Key Info (CONDITIONAL)
	Dg16 *DG16 // DATA GROUP 16 — Person(s) to Notify (OPTIONAL)
}

type PassiveAuth struct {
	CertChain [][]byte
}

func NewPassiveAuth(certChain [][]byte) *PassiveAuth {
	return &PassiveAuth{CertChain: certChain}
}

type Document struct {
	Atr []byte
	Ats []byte

	Mf MasterFile

	ChipAuthStatus ChipAuthStatus

	// passive auth
	PassiveAuthSOD     *PassiveAuth
	PassiveAuthCardSec *PassiveAuth

	Apdus []iso7816.ApduLog
}

type ChipAuthStatus int

const (
	CHIP_AUTH_STATUS_NONE ChipAuthStatus = iota
	CHIP_AUTH_STATUS_PACE_CAM
	CHIP_AUTH_STATUS_CA
	CHIP_AUTH_STATUS_AA
)

func (cas ChipAuthStatus) String() string {
	switch cas {
	case CHIP_AUTH_STATUS_NONE:
		return "n/a"
	case CHIP_AUTH_STATUS_PACE_CAM:
		return "PACE-CAM"
	case CHIP_AUTH_STATUS_CA:
		return "Chip Authentication"
	case CHIP_AUTH_STATUS_AA:
		return "Active Authentication"
	}

	return fmt.Sprintf("*UnsupportedValue* (cas:%d)", int(cas))
}

// gets the LDS Version (e.g. '0108') from EF.SOD or EF.COM
// returns empty string if valid cannot be determined
func (doc Document) LdsVersion() string {
	var ldsVer string

	// attempt to get from EF.SOD
	if doc.Mf.Lds1.Sod != nil {
		ldsVer = doc.Mf.Lds1.Sod.ldsVersion()
	}

	// attempt to get from EF.COM (if don't already have)
	if len(ldsVer) < 1 {
		if doc.Mf.Lds1.Com != nil {
			ldsVer = doc.Mf.Lds1.Com.LdsVersion
		}
	}

	return ldsVer
}

// gets the Unicode Version (e.g. '040000') from EF.SOD or EF.COM
// returns empty string if valid cannot be determined
func (doc Document) UnicodeVersion() string {
	var unicodeVer string

	// attempt to get from EF.SOD
	if doc.Mf.Lds1.Sod != nil {
		unicodeVer = doc.Mf.Lds1.Sod.unicodeVersion()
	}

	// attempt to get from EF.COM (if don't already have)
	if len(unicodeVer) < 1 {
		if doc.Mf.Lds1.Com != nil {
			unicodeVer = doc.Mf.Lds1.Com.UnicodeVersion
		}
	}

	return unicodeVer
}

func (doc *Document) NewDG(dg int, data []byte) (err error) {
	switch dg {
	case 1:
		doc.Mf.Lds1.Dg1, err = NewDG1(data)
	case 2:
		doc.Mf.Lds1.Dg2, err = NewDG2(data)
	case 7:
		doc.Mf.Lds1.Dg7, err = NewDG7(data)
	case 11:
		doc.Mf.Lds1.Dg11, err = NewDG11(data)
	case 12:
		doc.Mf.Lds1.Dg12, err = NewDG12(data)
	case 13:
		doc.Mf.Lds1.Dg13, err = NewDG13(data)
	case 14:
		doc.Mf.Lds1.Dg14, err = NewDG14(data)
	case 15:
		doc.Mf.Lds1.Dg15, err = NewDG15(data)
	case 16:
		doc.Mf.Lds1.Dg16, err = NewDG16(data)
	default:
		err = fmt.Errorf("unsupported DG in NewDG call (DG:%d)", dg)
	}

	return err
}

// verifies the files within the document (e.g. mandatory/conditional files and content)
// does NOT perform Passive-Authentication against the document files!
func (doc *Document) Verify() error {
	// verify that the mandatory files (COM,DG1,DG2,SOD) are present
	if (doc.Mf.Lds1.Com == nil) || (doc.Mf.Lds1.Dg1 == nil) || (doc.Mf.Lds1.Dg2 == nil) || (doc.Mf.Lds1.Sod == nil) {
		return fmt.Errorf("(doc.Verify) One or more mandatory files are missing (COM,SOD,DG1,DG2)")
	}

	// TODO - DG14
	//			- if not present then verify that it wasn't referenced in SOD.. if it is then error
	//			- if present
	//				- if card-access is present, then verify that it's contents are also within DG14
	//              - other checks (such as efDir)?

	// TODO - review 9303p11... 4.2 Chip Access Procedure

	return nil
}

func (doc *Document) IndentedJson() string {

	b, err := json.MarshalIndent(doc, "", "    ")
	if err != nil {
		log.Panicf("MarshalIndent error: %s", err)
	}

	return string(b)
}
