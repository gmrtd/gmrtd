package reader

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"runtime/debug"

	"github.com/gmrtd/gmrtd/activeauth"
	"github.com/gmrtd/gmrtd/bac"
	"github.com/gmrtd/gmrtd/chipauth"
	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/pace"
	"github.com/gmrtd/gmrtd/passiveauth"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/utils"
)

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

// reads the LDS1 files (EF.SOD,EF.COM,EF.DGxx)
func (reader *Reader) readLDS1files(nfc *iso7816.NfcSession, doc *document.Document) (err error) {
	slog.Info("Read EF.SOD")
	reader.status.Status("Reading EF.SOD")
	doc.Mf.Lds1.Sod, err = document.NewSOD(nfc.MustReadFile(MRTDFileIdEFSOD))
	if err != nil {
		return fmt.Errorf("(readLDS1files) error reading EF.SOD: %w", err)
	}

	slog.Info("Read EF.COM")
	reader.status.Status("Reading EF.COM")
	doc.Mf.Lds1.Com, err = document.NewCOM(nfc.MustReadFile(MRTDFileIdEFCOM))
	if err != nil {
		return fmt.Errorf("(readLDS1files) error reading EF.COM: %w", err)
	}

	err = reader.readLDS1dgs(nfc, doc)
	if err != nil {
		return fmt.Errorf("(readLDS1files) error reading DGs: %w", err)
	}

	return nil
}

// reads the LDS1 data-groups (DGs) based on the DG hashes present in EF.SOD
func (reader *Reader) readLDS1dgs(nfc *iso7816.NfcSession, doc *document.Document) (err error) {
	dgHashes := doc.Mf.Lds1.Sod.LdsSecurityObject.DataGroupHashValues

	for _, dgHash := range dgHashes {
		fileId, fileIdOk := dgToFileId[dgHash.DataGroupNumber]
		if !fileIdOk {
			// ignore if cannot resolve to file-id
			slog.Info("Skipping DG", "DG", dgHash.DataGroupNumber)
			continue
		}

		slog.Info("Reading DG", "DG", dgHash.DataGroupNumber)
		reader.status.Status(fmt.Sprintf("Reading DG%02d", dgHash.DataGroupNumber))

		var dgBytes []byte

		dgBytes, err = nfc.ReadFile(uint16(fileId))
		if err != nil {
			return fmt.Errorf("[readLDS1dgs] ReadFile(fileId:%d) error: %w", fileId, err)
		}

		err = doc.NewDG(dgHash.DataGroupNumber, dgBytes)
		if err != nil {
			return err
		}
	}

	return nil
}

func performChipAuthentication(nfc *iso7816.NfcSession, docEx *document.DocumentEx) (err error) {
	if !docEx.Session.ChipAuthenticated() {
		// attempt chip-authentication (if supported)
		// NB errors are just recorded at this point
		docEx.Session.ChipAuthResult, docEx.Session.ChipAuthErr = chipauth.NewChipAuth(nfc, &docEx.Document).DoChipAuth()
	}

	if !docEx.Session.ChipAuthenticated() {
		// attempt active-authentication (if supported)
		// NB errors are just recorded at this point
		docEx.Session.ActiveAuthResult, docEx.Session.ActiveAuthErr = activeauth.NewActiveAuth(nfc, &docEx.Document).DoActiveAuth()
	}

	return nil
}

type ReaderStatus interface {
	Status(msg string)
}

type Reader struct {
	status    ReaderStatus
	apduMaxLe int  // overrides if >0 (1..65536)
	skipPace  bool // skip PACE
}

func NewReader(status ReaderStatus) *Reader {
	var reader Reader
	reader.status = status
	return &reader
}

// sets the APDU Max LE (1..65536) (0 to disable override)
func (reader *Reader) SetApduMaxLe(maxRead int) {
	if (maxRead < 0) || (maxRead > 65536) {
		log.Panicf("Invalid APDU Max LE range (Exp:0..65536) (Act:%d)", maxRead)
	}
	reader.apduMaxLe = maxRead
}

func (reader *Reader) SkipPace() {
	reader.skipPace = true
}

// reads the document using the specified transceiver and password
// - also performs doc.Verify() and Passive Authentication!
// NB returns partial data (docEx) in the event of an error
func (reader *Reader) ReadDocument(transceiver iso7816.Transceiver, password *password.Password, atr []byte, ats []byte) (docEx *document.DocumentEx, err error) {
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

	docEx = new(document.DocumentEx)

	// record ATR/ATS
	// NB we don't really do much with these today, just recording
	recordAtrAts(atr, ats, &docEx.Session)

	// NB spec recommends not to use, but iOS may pre-select the MRTD AID
	slog.Info("Selecting MF")
	if err = nfc.SelectMF(); err != nil {
		return docEx, err
	}

	slog.Info("Read CardAccess")
	// may not be present (OR may be present but not have PACE info)
	if docEx.Document.Mf.CardAccess, err = document.NewCardAccess(nfc.MustReadFile(MRTDFileIdCardAccess)); err != nil {
		return docEx, err
	}

	/*
	 * PACE
	 */
	if !reader.skipPace {
		reader.status.Status("PACE")
		// NB errors are just recorded at this point
		docEx.Session.PaceResult, docEx.Session.PaceErr = pace.NewPace(nfc, &docEx.Document, password).DoPACE()
	}

	// NB moved after PACE as we've seen access related errors on NZ passports when done before PACE
	slog.Info("Read EF.DIR")
	docEx.Document.Mf.Dir, err = document.NewEFDIR(nfc.MustReadFile(MRTDFileIdEFDIR))
	if err != nil {
		return docEx, err
	}
	if docEx.Document.Mf.Dir != nil {
		slog.Debug("EF.DIR", "bytes", utils.BytesToHex(docEx.Document.Mf.Dir.RawData))
	}

	slog.Info("Selecting MRTD AID")
	_, err = nfc.SelectAid(utils.HexToBytes(MRTD_AID))
	if err != nil {
		return docEx, err
	}

	/*
	 * Basic Access Control (BAC) - if required
	 */

	// NB we only attempt BAC if we don't already have SecureMessaging (i.e. via PACE)
	if nfc.SM == nil {
		reader.status.Status("BAC")
		// NB errors are just recorded at this point
		docEx.Session.BacResult, docEx.Session.BacErr = bac.NewBAC(nfc, &docEx.Document, password).DoBAC()
	}

	// NB legacy passport may not have BAC/PACE so we should be prepared for no SecureMessaging

	/*
	 * Read LDS1 files
	 */
	err = reader.readLDS1files(nfc, &docEx.Document)
	if err != nil {
		return docEx, err
	}

	/*
	 * Chip / Active Authentication
	 *
	 * NB requires DG data, so performed after DG read
	 */
	reader.status.Status("Active Authentication")
	err = performChipAuthentication(nfc, docEx)
	if err != nil {
		return docEx, err
	}

	// verify the document
	reader.status.Status("Verifying Document")
	err = docEx.Document.Verify()
	if err != nil {
		slog.Error("Document.Verify", "error", err)
		return docEx, err
	}

	// TODO - should setup this earlier... e.g. Reader setup?
	var cscaCertPool *cms.CombinedCertPool
	{
		var err error

		cscaCertPool, err = cms.DefaultMasterList()
		if err != nil {
			return docEx, err
		}
	}

	// perform passive authentication
	// NB errors are just recorded at this point
	reader.status.Status("Passive Authentication")
	docEx.Session.PassiveAuthResult, docEx.Session.PassiveAuthErr = passiveauth.PassiveAuth(&docEx.Document, cscaCertPool)

	// copy apdu-log over to session
	docEx.Session.Apdus = nfc.ApduLog

	// TODO - do final classification of the document... e.g. dataAuthenticated / chipAuthenticated??... can also record lds/unicode-version
	reader.status.Status("Valid Document!")

	slog.Info("** ReadDocument FINISHED **", "ChipAuthenticated", docEx.Session.ChipAuthenticated())

	return
}

func recordAtrAts(atr []byte, ats []byte, session *document.Session) {
	var chipActivationRsp document.ChipActivationRsp

	chipActivationRsp.Atr = bytes.Clone(atr)
	chipActivationRsp.Ats = bytes.Clone(ats)

	session.ChipActivationRsp = &chipActivationRsp

	slog.Debug("ATR/ATS",
		"ATR", utils.BytesToHex(session.ChipActivationRsp.Atr),
		"ATS", utils.BytesToHex(session.ChipActivationRsp.Ats),
	)
}
