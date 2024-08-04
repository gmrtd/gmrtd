package gmrtd

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"runtime/debug"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/utils"
)

// TODO - if we read card-access.. then should check it matches with DG14.. as that is protected by SoD
//			review 9303p11... 4.2 Chip Access Procedure

// TODO - refer to BSI doc.. s5.6 for different inspection flows
// https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03135/BSI-TR-03135-1-v2-5.pdf?__blob=publicationFile&v=3
//
// e.g. special rules for inferring AA?.... and also CA
//
//After BAC or PACE has been performed and the EF.SOD has been read, check if EF.DG14 is available. If EF.DG14
//is present and the parameters required for CA are included in this data group, CA is performed in version 1 in
//order to authenticate the chip. If EF.DG14 is available, but the parameters required for CA are not included, the
//information available in EF.DG14 can be evaluated as follows: If elliptic curves are used, AA MAY be performed
//by using the information available in EF.DG14 as domain parameters.
//28 Federal Office for Information Security
//Authentication of MRTDs
//If EF.DG14 is not available, check if EF.DG15 is available. If EF.DG15 is available, AA is performed. If EF.DG15 is
//not available, the authenticity of the chip cannot be verified, since neither AA nor CAv1 could be performed.
//If EF.DG14 and EF.DG15 are available, AA MAY be performed in addition to CAv1.
//After the authenticity check has been performed, existing and accessible data groups SHALL be read – at least
//EF.DG1 and EF.DG2. If fingerprints are stored in EF.DG3 and if they are protected with EAC according to [BSI
//TR-03110], they can be accessed only after TAv1 was performed successfully. For this purpose, the EF.CVCA
//file SHALL be read first in order to obtain the information required for performing TAv1.

// TODO - review chip access procedure (p11 - page 16)

// TODO - docs say should move over to EF.SOD (LDS 1.8)... (p10 page 33)

// TODO - should check certain parts of the document.. e.g. COM,SOD,DG1/2 are mandatory.. others are optional / conditional (e.g. DG14 based on conditions)

// TODO - verify DG14 matches unsecured files

// TODO - look at moving to short-file id if that is actually the mandatory one

const MRTDFileIdCardAccess = uint16(0x011C)
const MRTDFileIdCardSecurity = uint16(0x011D)
const MRTDFileIdEFSOD = uint16(0x011D)
const MRTDFileIdEFCOM = uint16(0x011E)
const MRTDFileIdEFDIR = uint16(0x2F00)

const MRTDFileIdDG1 = uint16(0x0101)
const MRTDFileIdDG2 = uint16(0x0102)
const MRTDFileIdDG7 = uint16(0x0107)
const MRTDFileIdDG11 = uint16(0x010B)
const MRTDFileIdDG12 = uint16(0x010C)
const MRTDFileIdDG13 = uint16(0x010D)
const MRTDFileIdDG14 = uint16(0x010E)
const MRTDFileIdDG15 = uint16(0x010F)
const MRTDFileIdDG16 = uint16(0x0110)

const MRTD_AID = "A0000002471001"

// Maps DG (1-16) to File Identifier
var dgToFileId = map[int]uint16{
	1:  MRTDFileIdDG1,
	2:  MRTDFileIdDG2,
	7:  MRTDFileIdDG7,
	11: MRTDFileIdDG11,
	12: MRTDFileIdDG12,
	13: MRTDFileIdDG13,
	14: MRTDFileIdDG14,
	15: MRTDFileIdDG15,
	16: MRTDFileIdDG16,
}

// reads the data-groups (DGs) based on the DG hashes present in EF.SOD
// error if <2 DG hashes are present in SOD (as DG1/2 are always mandatory)
func readDGs(nfc *iso7816.NfcSession, doc *Document) (err error) {
	dgHashes := doc.Sod.LdsSecurityObject.DataGroupHashValues
	if len(dgHashes) < 2 {
		return fmt.Errorf("EF.SOD must have at least two datagroup hashes")
	}

	for _, dgHash := range dgHashes {
		fileId, fileIdOk := dgToFileId[dgHash.DataGroupNumber]
		if !fileIdOk {
			// ignore if cannot resolve to file-id
			slog.Info("Skipping DG", "DG", dgHash.DataGroupNumber)
			continue
		}

		slog.Info("Reading DG", "DG", dgHash.DataGroupNumber)

		var dgBytes []byte = nfc.ReadFile(uint16(fileId))

		err = doc.NewDG(dgHash.DataGroupNumber, dgBytes)
		if err != nil {
			return err
		}

		// validate the DG hash against the hash in the SOD
		// TODO - need to decide whether to keep this here or move to passive-auth to have everything in one place
		{
			actHash := cryptoutils.CryptoHashByOid(doc.Sod.LdsSecurityObject.HashAlgorithm.Algorithm, dgBytes)

			if !bytes.Equal(actHash, dgHash.DataGroupHashValue) {
				return fmt.Errorf("DG%d hash invalid (Exp:%x, Act:%x)", dgHash.DataGroupNumber, utils.BytesToHex(dgHash.DataGroupHashValue), utils.BytesToHex(actHash))
			}

			slog.Info("Valid DG hash", "DG", dgHash.DataGroupNumber, "Hash-Act", utils.BytesToHex(actHash), "Hash-Exp", utils.BytesToHex(dgHash.DataGroupHashValue))
		}
	}

	return nil
}

type Reader struct {
	apduMaxLe int // overrides if >0 (1..65536)
}

func NewReader() *Reader {
	var reader Reader
	return &reader
}

// sets the APDU Max LE (1..65536) (0 to disable override)
func (reader *Reader) SetApduMaxLe(maxRead int) {
	if (maxRead < 0) || (maxRead > 65536) {
		log.Panicf("Invalid APDU Max LE range (Exp:0..65536) (Act:%d)", maxRead)
	}
	reader.apduMaxLe = maxRead
}

// NB returns partial data (MrtdDocument) in the event of an error
func (reader *Reader) ReadDocument(transceiver iso7816.Transceiver, password *Password, atr []byte, ats []byte) (doc *Document, err error) {
	defer func() {
		if e := recover(); e != nil {
			switch x := e.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("unknown panic")
			}
			debug.PrintStack()
		}
	}()

	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(transceiver)

	// override default (if required)
	if reader.apduMaxLe > 0 {
		nfc.MaxLe = reader.apduMaxLe
	}

	doc = new(Document)

	// record ATR/ATS
	// NB we don't really do much with these today, just recording
	doc.Atr = bytes.Clone(atr)
	doc.Ats = bytes.Clone(ats)
	slog.Debug("ATR/ATS",
		"ATR", utils.BytesToHex(doc.Atr),
		"ATS", utils.BytesToHex(doc.Ats),
	)

	// NB spec recommends not to use, but iOS may pre-select the MRTD AID
	slog.Info("Selecting MF")
	if err = nfc.SelectMF(); err != nil {
		return doc, err
	}

	slog.Info("Read CardAccess")
	// may not be present (OR may be present but not have PACE info)
	if doc.CardAccess, err = NewCardAccess(nfc.ReadFile(MRTDFileIdCardAccess)); err != nil {
		return doc, err
	}

	/*
	 * PACE
	 */
	// TODO - should we have an option to skip PACE
	{
		err = NewPace().doPACE(nfc, password, doc)
		if err != nil {
			return doc, err
		}
	}

	// NB moved after PACE as we've seen access related errors on NZ passports when done before PACE
	slog.Info("Read EF.DIR")
	doc.Dir = NewEFDIR(nfc.ReadFile(MRTDFileIdEFDIR))
	if doc.Dir != nil {
		slog.Debug("EF.DIR", "bytes", utils.BytesToHex(doc.Dir.RawData))
	}

	slog.Info("Selecting MRTD AID")
	_, err = nfc.SelectAid(utils.HexToBytes(MRTD_AID))
	if err != nil {
		return doc, err
	}

	/*
	 * Basic Access Control (BAC) - if required
	 */

	// NB we only attempt BAC if we don't already have SecureMessaging (i.e. via PACE)
	if nfc.SM == nil {
		err = NewBAC().doBAC(nfc, password)
		if err != nil {
			return doc, err
		}
	}

	// NB legacy passport may not have BAC/PACE so we should be prepared for no SecureMessaging

	/*
	 * Read files
	 */

	slog.Info("Read EF.SOD")
	doc.Sod, err = NewSOD(nfc.ReadFile(MRTDFileIdEFSOD))
	if err != nil {
		return doc, err
	}

	slog.Info("Read EF.COM")
	doc.Com, err = NewCOM(nfc.ReadFile(MRTDFileIdEFCOM))
	if err != nil {
		return doc, err
	}

	readDGs(nfc, doc)

	/*
	 * Chip / Active Authentication
	 *
	 * NB requires DG data, so performed after DG read
	 */

	if doc.ChipAuthStatus == CHIP_AUTH_STATUS_NONE {
		err = NewChipAuth().doChipAuth(nfc, doc)
	}

	if doc.ChipAuthStatus == CHIP_AUTH_STATUS_NONE {
		err = NewActiveAuth().doActiveAuth(nfc, doc)
	}

	// copy apdu-log over to document
	doc.Apdus = nfc.ApduLog

	slog.Info("** FINISHED **", "ChipAuthStatus", doc.ChipAuthStatus)

	return
}
