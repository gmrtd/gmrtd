package gmrtd

import "fmt"

type Document struct {
	CardAccess     *CardAccess
	CardSecurity   *CardSecurity // NB only read for PACE-CAM - read during PACE flow
	Dir            *EFDIR        // indicates which applications are present - generally not acvailable
	Com            *COM          // largely deprecated by SOD, but used to determine Lds/Unicode Version if older SOD formatis present
	Sod            *SOD          // Document Security Object EF.SOD (MANDATORY)
	Dg1            *DG1          // DATA GROUP 1 — Machine Readable Zone Information (MANDATORY)
	Dg2            *DG2          // DATA GROUP 2 — Encoded Identification Features — Face (MANDATORY)
	Dg7            *DG7          // DATA GROUP 7 — Displayed Signature or Usual Mark (OPTIONAL)
	Dg11           *DG11         // DATA GROUP 11 — Additional Personal Detail(s) (OPTIONAL)
	Dg12           *DG12         // DATA GROUP 12 — Additional Document Detail(s) (OPTIONAL)
	Dg13           *DG13         // DATA GROUP 13 — Optional Details(s) (OPTIONAL)
	Dg14           *DG14         // DATA GROUP 14 — Security Options (CONDITIONAL)
	Dg15           *DG15         // DATA GROUP 15 — Active Authentication Public Key Info (CONDITIONAL)
	Dg16           *DG16         // DATA GROUP 16 — Person(s) to Notify (OPTIONAL)
	ChipAuthStatus ChipAuthStatus
}

type ChipAuthStatus int

const (
	CHIP_AUTH_STATUS_NA ChipAuthStatus = iota
	CHIP_AUTH_STATUS_PACE_CAM
	CHIP_AUTH_STATUS_CA
	CHIP_AUTH_STATUS_AA
)

// gets the LDS Version (e.g. '0108') from EF.SOD or EF.COM
// returns empty string if valid cannot be determined
func (doc Document) LdsVersion() string {
	var ldsVer string

	// attempt to get from EF.SOD
	if doc.Sod != nil {
		ldsVer = doc.Sod.ldsVersion()
	}

	// attempt to get from EF.COM (if don't already have)
	if len(ldsVer) < 1 {
		if doc.Com != nil {
			ldsVer = doc.Com.LdsVersion
		}
	}

	return ldsVer
}

// gets the Unicode Version (e.g. '040000') from EF.SOD or EF.COM
// returns empty string if valid cannot be determined
func (doc Document) UnicodeVersion() string {
	var unicodeVer string

	// attempt to get from EF.SOD
	if doc.Sod != nil {
		unicodeVer = doc.Sod.unicodeVersion()
	}

	// attempt to get from EF.COM (if don't already have)
	if len(unicodeVer) < 1 {
		if doc.Com != nil {
			unicodeVer = doc.Com.UnicodeVersion
		}
	}

	return unicodeVer
}

func (doc *Document) NewDG(dg int, data []byte) (err error) {
	switch dg {
	case 1:
		doc.Dg1, err = NewDG1(data)
	case 2:
		doc.Dg2, err = NewDG2(data)
	case 7:
		doc.Dg7, err = NewDG7(data)
	case 11:
		doc.Dg11, err = NewDG11(data)
	case 12:
		doc.Dg12, err = NewDG12(data)
	case 13:
		doc.Dg13, err = NewDG13(data)
	case 14:
		doc.Dg14, err = NewDG14(data)
	case 15:
		doc.Dg15, err = NewDG15(data)
	case 16:
		doc.Dg16, err = NewDG16(data)
	default:
		err = fmt.Errorf("unsupported DG in NewDG call (DG:%d)", dg)
	}

	return err
}
