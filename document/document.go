// Package document implements data structures for representing the content of the MRTD.
package document

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"

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

	// error if DG14 is not present, but is referenced by SOD
	if (doc.Mf.Lds1.Dg14 == nil) && doc.Mf.Lds1.Sod.HasDgHash(14) {
		return fmt.Errorf("(doc.Verify) DG14 file missing but referenced by SOD")
	}

	// error if CardAccess SecInfos are not present within DG14
	if (doc.Mf.CardAccess != nil) && (doc.Mf.Lds1.Dg14 != nil) {
		slog.Info("Document.Verify: Verifying that CardAccess content is present within DG14")
		if !doc.Mf.Lds1.Dg14.SecInfos.Contains(doc.Mf.CardAccess.SecurityInfos) {
			return fmt.Errorf("(doc.Verify) CardAccess SecInfos are not present within DG14")
		}
	}

	if (doc.Mf.Dir != nil) && (doc.Mf.Lds1.Dg14 != nil) {
		// TODO - verify that EF.DIR is present in DG14 (has this always been a requirement?)
	}

	// error if DG15 is not present, but is referenced by SOD
	if (doc.Mf.Lds1.Dg15 == nil) && doc.Mf.Lds1.Sod.HasDgHash(15) {
		return fmt.Errorf("(doc.Verify) DG15 file missing but referenced by SOD")
	}

	// TODO - any other validation required?
	// 			- review 9303p11... 4.2 Chip Access Procedure

	return nil
}

func (doc *Document) IndentedJson() string {

	b, err := json.MarshalIndent(doc, "", "    ")
	if err != nil {
		log.Panicf("MarshalIndent error: %s", err)
	}

	return string(b)
}

// should be 8-byte (YYYYMMDD) encoded, but we're seen passports with 4-byte BCD encoding
func parseDateYYYYMMDD(data []byte) string {
	var out string

	if len(data) == 4 {
		out = fmt.Sprintf("%x", data)
	} else {
		out = string(data)
	}

	return out
}

// should be 14-byte (YYYYMMDDHHMISS) encoded, but we expects passports with 7-byte BCD encoding
func parseDatetimeYYYYMMDDHHMISS(data []byte) string {
	var out string

	if len(data) == 7 {
		out = fmt.Sprintf("%x", data)
	} else {
		out = string(data)
	}

	return out
}
