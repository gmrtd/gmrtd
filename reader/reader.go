package reader

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"

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

type ReaderStatus interface {
	Status(msg string)
}

type Reader struct {
	status       ReaderStatus
	nfc          *iso7816.NfcSession
	cscaCertPool cms.CertPool
	skipPace     bool // skip PACE
}

func NewReader(status ReaderStatus, nfc *iso7816.NfcSession, cscaCertPool cms.CertPool) *Reader {
	var reader Reader
	reader.status = status
	reader.nfc = nfc
	reader.cscaCertPool = cscaCertPool
	return &reader
}

func (reader *Reader) SkipPace() {
	reader.skipPace = true
}

type ReaderState struct {
	atr      []byte
	ats      []byte
	password *password.Password
	docEx    *document.DocumentEx
}

func NewReaderState(atr []byte, ats []byte, password *password.Password) *ReaderState {
	var out ReaderState

	out.atr = bytes.Clone(atr)
	out.ats = bytes.Clone(ats)
	out.password = password
	out.docEx = new(document.DocumentEx)

	return &out
}

// reads the document using the specified transceiver and password
// - also performs doc.Verify() and Passive Authentication!
// NB returns partial data (docEx) in the event of an error
func (reader *Reader) ReadDocument(password *password.Password, atr []byte, ats []byte) (docEx *document.DocumentEx, err error) {
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
		}
	}()

	var state *ReaderState = NewReaderState(atr, ats, password)

	err = runSteps(
		reader,
		state,
		recordAtrAts,
		selectMF,
		readEfCardAccess,
		performPace,
		selectMrtdApplication,
		performBac,
		readEfDir,
		readEfSod,
		readEfCom,
		readLDS1dgs,
		performChipAuthentication,
		verifyDocument,
		performPassiveAuthentication,
	)
	if err != nil {
		return state.docEx, fmt.Errorf("[ReadDocument] runSteps error: %w", err)
	}

	// copy apdu-log over to session
	state.docEx.Session.ApduLog = reader.nfc.ApduLog()

	// TODO - do final classification of the document... e.g. dataAuthenticated / chipAuthenticated??... can also record lds/unicode-version
	reader.status.Status("Valid Document!")

	slog.Info("** ReadDocument FINISHED **", "ChipAuthenticated", state.docEx.Session.ChipAuthenticated())

	return state.docEx, nil
}

type ReaderStep func(*Reader, *ReaderState) error

func runSteps(reader *Reader, state *ReaderState, steps ...ReaderStep) error {
	for _, step := range steps {
		if err := step(reader, state); err != nil {
			return fmt.Errorf("[runSteps] error: %w", err)
		}
	}
	return nil
}
func recordAtrAts(_ *Reader, state *ReaderState) (err error) {
	// record ATR/ATS
	// NB we don't really do much with these today, just recording

	var chipActivationRsp document.ChipActivationRsp

	chipActivationRsp.Atr = bytes.Clone(state.atr)
	chipActivationRsp.Ats = bytes.Clone(state.ats)

	state.docEx.Session.ChipActivationRsp = &chipActivationRsp

	slog.Debug("ATR/ATS",
		"ATR", utils.BytesToHex(state.docEx.Session.ChipActivationRsp.Atr),
		"ATS", utils.BytesToHex(state.docEx.Session.ChipActivationRsp.Ats),
	)

	return nil
}

func selectMF(reader *Reader, _ *ReaderState) (err error) {
	// NB spec recommends not to use, but iOS may pre-select the MRTD AID
	slog.Info("Selecting MF")
	if err = reader.nfc.SelectMF(); err != nil {
		return fmt.Errorf("[selectMF] nfc.SelectMF error: %w", err)
	}
	return nil
}

func selectMrtdApplication(reader *Reader, _ *ReaderState) (err error) {
	slog.Info("Selecting MRTD AID")
	_, err = reader.nfc.SelectAid(utils.HexToBytes(MRTD_AID))
	if err != nil {
		return fmt.Errorf("[selectMrtdApplication] Select MRTD AID error: %w", err)
	}
	return nil
}

// reads EF.SOD
func readEfSod(reader *Reader, state *ReaderState) (err error) {
	slog.Info("Read EF.SOD")
	reader.status.Status("Reading EF.SOD")
	sodData, err := reader.nfc.ReadFile(MRTDFileIdEFSOD)
	if err != nil {
		return fmt.Errorf("[readEfSod] ReadFile error: %w", err)
	}
	state.docEx.Document.Mf.Lds1.Sod, err = document.NewSOD(sodData)
	if err != nil {
		return fmt.Errorf("[readEfSod] NewSOD error: %w", err)
	}

	return nil
}

// reads EF.COM
func readEfCom(reader *Reader, state *ReaderState) (err error) {
	slog.Info("Read EF.COM")
	reader.status.Status("Reading EF.COM")
	efComData, err := reader.nfc.ReadFile(MRTDFileIdEFCOM)
	if err != nil {
		return fmt.Errorf("[readEfCom] ReadFile error: %w", err)
	}
	state.docEx.Document.Mf.Lds1.Com, err = document.NewCOM(efComData)
	if err != nil {
		return fmt.Errorf("[readEfCom] NewCOM error: %w", err)
	}

	return nil
}

// reads EF.DIR
func readEfDir(reader *Reader, state *ReaderState) (err error) {
	slog.Info("Read EF.DIR")
	reader.status.Status("Reading EF.DIR")
	efDirData, err := reader.nfc.ReadFile(MRTDFileIdEFDIR)
	if err != nil {
		return fmt.Errorf("[readEfDir] Read EF.DIR error: %w", err)
	}
	state.docEx.Document.Mf.Dir, err = document.NewEFDIR(efDirData)
	if err != nil {
		return fmt.Errorf("[readEfDir] Parse EF.DIR error: %w", err)
	}

	return nil
}

// reads EF.CardAccess
func readEfCardAccess(reader *Reader, state *ReaderState) (err error) {
	slog.Info("Read EF.CardAccess")
	reader.status.Status("Reading EF.CardAccess")
	// may not be present (OR may be present but not have PACE info)
	cardAccessData, err := reader.nfc.ReadFile(MRTDFileIdCardAccess)
	if err != nil {
		return fmt.Errorf("[readEfCardAccess] Read Card.Access error: %w", err)
	}
	state.docEx.Document.Mf.CardAccess, err = document.NewCardAccess(cardAccessData)
	if err != nil {
		return fmt.Errorf("[readEfCardAccess] Parse Card.Access error: %w", err)
	}

	return nil
}

// reads the LDS1 data-groups (DGs) based on the DG hashes present in EF.SOD
func readLDS1dgs(reader *Reader, state *ReaderState) (err error) {
	if state.docEx.Document.Mf.Lds1.Sod == nil {
		return fmt.Errorf("[readLDS1dgs] SOD is missing")
	}

	dgHashes := state.docEx.Document.Mf.Lds1.Sod.LdsSecurityObject.DataGroupHashValues

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

		dgBytes, err = reader.nfc.ReadFile(uint16(fileId))
		if err != nil {
			return fmt.Errorf("[readLDS1dgs] ReadFile(fileId:%d) error: %w", fileId, err)
		}

		err = state.docEx.Document.NewDG(dgHash.DataGroupNumber, dgBytes)
		if err != nil {
			return fmt.Errorf("[readLDS1dgs] Parse DG(fileId:%d) error: %w", dgHash.DataGroupNumber, err)
		}
	}

	return nil
}

func performPace(reader *Reader, state *ReaderState) error {
	if reader.skipPace {
		return nil
	}
	reader.status.Status("PACE")
	// NB errors are just recorded at this point
	state.docEx.Session.PaceResult, state.docEx.Session.PaceErr = pace.NewPace(reader.nfc, &state.docEx.Document, state.password).DoPACE()
	return nil
}

func performBac(reader *Reader, state *ReaderState) error {
	// NB we only attempt BAC if we don't already have SecureMessaging (i.e. via PACE)
	if reader.nfc.SM() != nil {
		return nil
	}
	reader.status.Status("BAC")
	// NB errors are just recorded at this point
	state.docEx.Session.BacResult, state.docEx.Session.BacErr = bac.NewBAC(reader.nfc, &state.docEx.Document, state.password).DoBAC()
	return nil
}

func performChipAuthentication(reader *Reader, state *ReaderState) error {
	slog.Info("Chip Authentication (CA/AA)")
	reader.status.Status("Chip Authentication (CA/AA)")

	if !state.docEx.Session.ChipAuthenticated() {
		// attempt chip-authentication (if supported)
		// NB errors are just recorded at this point
		state.docEx.Session.ChipAuthResult, state.docEx.Session.ChipAuthErr = chipauth.NewChipAuth(reader.nfc, &state.docEx.Document).DoChipAuth()
	}

	if !state.docEx.Session.ChipAuthenticated() {
		// attempt active-authentication (if supported)
		// NB errors are just recorded at this point
		state.docEx.Session.ActiveAuthResult, state.docEx.Session.ActiveAuthErr = activeauth.NewActiveAuth(reader.nfc, &state.docEx.Document).DoActiveAuth()
	}

	return nil
}

func performPassiveAuthentication(reader *Reader, state *ReaderState) error {
	// perform passive authentication
	// NB errors are just recorded at this point
	reader.status.Status("Passive Authentication")
	state.docEx.Session.PassiveAuthResult, state.docEx.Session.PassiveAuthErr = passiveauth.PassiveAuth(&state.docEx.Document, reader.cscaCertPool)
	return nil
}

func verifyDocument(reader *Reader, state *ReaderState) (err error) {
	reader.status.Status("Verifying Document")
	err = state.docEx.Document.Verify()
	if err != nil {
		slog.Error("Document.Verify", "error", err)
		return fmt.Errorf("[verifyDocument] Document.Verify error: %w", err)
	}
	return nil
}
