// Package document implements data structures for representing the content of the MRTD.
package document

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/utils"
)

type MasterFile struct {
	CardAccess   *CardAccess   `json:"cardAccess,omitempty"`
	CardSecurity *CardSecurity `json:"cardSecurity,omitempty"` // NB only read for PACE-CAM - read during PACE flow
	Dir          *EFDIR        `json:"dir,omitempty"`          // indicates which applications are present - generally not available
	Lds1         LDS1          `json:"lds1"`
}

type LDS1 struct {
	Com  *COM  `json:"com,omitempty"`  // largely deprecated by SOD, but used to determine Lds/Unicode Version if older SOD formatis present
	Sod  *SOD  `json:"sod,omitempty"`  // Document Security Object EF.SOD (MANDATORY)
	Dg1  *DG1  `json:"dg1,omitempty"`  // DATA GROUP 1 — Machine Readable Zone Information (MANDATORY)
	Dg2  *DG2  `json:"dg2,omitempty"`  // DATA GROUP 2 — Encoded Identification Features — Face (MANDATORY)
	Dg7  *DG7  `json:"dg7,omitempty"`  // DATA GROUP 7 — Displayed Signature or Usual Mark (OPTIONAL)
	Dg11 *DG11 `json:"dg11,omitempty"` // DATA GROUP 11 — Additional Personal Detail(s) (OPTIONAL)
	Dg12 *DG12 `json:"dg12,omitempty"` // DATA GROUP 12 — Additional Document Detail(s) (OPTIONAL)
	Dg13 *DG13 `json:"dg13,omitempty"` // DATA GROUP 13 — Optional Details(s) (OPTIONAL)
	Dg14 *DG14 `json:"dg14,omitempty"` // DATA GROUP 14 — Security Options (CONDITIONAL)
	Dg15 *DG15 `json:"dg15,omitempty"` // DATA GROUP 15 — Active Authentication Public Key Info (CONDITIONAL)
	Dg16 *DG16 `json:"dg16,omitempty"` // DATA GROUP 16 — Person(s) to Notify (OPTIONAL)
}

type Document struct {
	Mf MasterFile `json:"mf"`
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
		err = fmt.Errorf("[NewDG] unsupported DG (DG:%d)", dg)
	}

	return err
}

var dgHashableIds []int = []int{1, 2, 7, 11, 12, 13, 14, 15, 16}

func (doc *Document) DgHashes() (map[int][]byte, error) {
	dgHashes := make(map[int][]byte)

	// evaluate for each hashable DG
	for _, dgId := range dgHashableIds {
		hash, err := doc.DgHash(dgId)
		if err != nil {
			return nil, fmt.Errorf("[DgHashes] DgHash (dg:%1d) error: %w", dgId, err)
		}

		// record if we got a hash (e.g. DG is actually present)
		if len(hash) > 0 {
			dgHashes[dgId] = hash
		}
	}

	for dgId, dgHash := range dgHashes {
		slog.Debug("doc.DgHashes", "dgId", dgId, "hash", utils.BytesToHex(dgHash))
	}

	return dgHashes, nil
}

// returns: hash for DG, or nil if not present
// NB SoD must be defined, as it will be used to determine the hash algorithm
func (doc *Document) DgHash(dgNumber int) ([]byte, error) {
	var dgBytes []byte

	switch dgNumber {
	case 1:
		if doc.Mf.Lds1.Dg1 != nil {
			dgBytes = doc.Mf.Lds1.Dg1.RawData
		}
	case 2:
		if doc.Mf.Lds1.Dg2 != nil {
			dgBytes = doc.Mf.Lds1.Dg2.RawData
		}
	case 7:
		if doc.Mf.Lds1.Dg7 != nil {
			dgBytes = doc.Mf.Lds1.Dg7.RawData
		}
	case 11:
		if doc.Mf.Lds1.Dg11 != nil {
			dgBytes = doc.Mf.Lds1.Dg11.RawData
		}
	case 12:
		if doc.Mf.Lds1.Dg12 != nil {
			dgBytes = doc.Mf.Lds1.Dg12.RawData
		}
	case 13:
		if doc.Mf.Lds1.Dg13 != nil {
			dgBytes = doc.Mf.Lds1.Dg13.RawData
		}
	case 14:
		if doc.Mf.Lds1.Dg14 != nil {
			dgBytes = doc.Mf.Lds1.Dg14.RawData
		}
	case 15:
		if doc.Mf.Lds1.Dg15 != nil {
			dgBytes = doc.Mf.Lds1.Dg15.RawData
		}
	case 16:
		if doc.Mf.Lds1.Dg16 != nil {
			dgBytes = doc.Mf.Lds1.Dg16.RawData
		}
	default:
		// NB hard error to catch cases where a new DG is added but not wired up properly
		return nil, fmt.Errorf("[DgHash] unsupported DG (DG:%d)", dgNumber)
	}

	if len(dgBytes) < 1 {
		return nil, nil
	}

	var dgHash []byte
	var err error

	if doc.Mf.Lds1.Sod == nil {
		return nil, fmt.Errorf("[DgHash] SoD is required")
	}

	dgHash, err = cryptoutils.CryptoHashByOid(doc.Mf.Lds1.Sod.LdsSecurityObject.HashAlgorithm.Algorithm, dgBytes)
	if err != nil {
		return nil, fmt.Errorf("[DgHash] CryptoHashByOid error: %w", err)
	}

	return dgHash, nil

}

// verifies the files within the document (e.g. mandatory/conditional files and content)
// does NOT perform Passive-Authentication against the document files!
func (doc *Document) Verify() error {
	// TODO - these are quite strict and based more on direct NFC read... may need a relaxed version for docs loaded from other sources

	// TODO - not sure why we enforce presence of EF.COM
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
		if err := doc.Mf.Lds1.Dg14.SecInfos.Contains(doc.Mf.CardAccess.SecurityInfos); err != nil {
			return fmt.Errorf("[doc.Verify] CardAccess SecInfos are not present within DG14: %w", err)
		}
	}

	if (doc.Mf.Dir != nil) && (doc.Mf.Lds1.Dg14 != nil) {
		// TODO - verify that EF.DIR is present in DG14 (has this always been a requirement?)

		// TODO - looks like this could be a misunderstanding.. and maybe we should be checking CardSecurity also
		//
		// 9303p11 s4.2.3
		// The inspection system MUST verify the authenticity of the contents of EF.Car
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
