package gmrtd

import (
	"errors"
	"log/slog"
	"runtime/debug"
)

// TODO - if we read card-access.. then should check it matches with DG14.. as that is protected by SoD
//			review 9303p11... 4.2 Chip Access Procedure

// TODO - refer to BSI doc.. s5.6 for different inspection flows
// https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03135/BSI-TR-03135-1-v2-5.pdf?__blob=publicationFile&v=3
//
// e.g. special rules for inferring AA?....
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

// TODO - shouldn't we determine what DGs are present from EF.COM/EF.SOD?

// TODO - aren't we only supposed to attempt reading DGs that are referenced by the SoD?

// TODO - docs say should move over to EF.SOD (LDS 1.8)... (p10 page 33)

// TODO - should probably do CA/AA first and then read data files

// TODO - should check certain parts of the document.. e.g. DG1/2 are both mandatory

// TODO - verify DG14 matches unsecured files

// TODO - look at moving to short-file id if that is actually the mandatory one
const MRTDFileIdCardAccess = 0x011C
const MRTDFileIdCardSecurity = 0x011D
const MRTDFileIdEFSOD = 0x011D
const MRTDFileIdEFCOM = 0x011E
const MRTDFileIdEFDIR = 0x2F00

const MRTDFileIdDG1 = 0x0101
const MRTDFileIdDG2 = 0x0102
const MRTDFileIdDG7 = 0x0107
const MRTDFileIdDG11 = 0x010B
const MRTDFileIdDG12 = 0x010C
const MRTDFileIdDG13 = 0x010D
const MRTDFileIdDG14 = 0x010E
const MRTDFileIdDG15 = 0x010F
const MRTDFileIdDG16 = 0x0110

const MRTD_AID = "A0000002471001"

// TODO - should dynamically read the files based on the tags from SOD
//   - SOD is also in the tags, but would need to be read before reading the others
//   - in addition to the regular DGx files... COM should also be specified in the SOD tags
func readDGs(nfc *NfcSession, doc *Document) (err error) {
	slog.Info("Read EF.DG1")
	doc.Dg1, err = NewDG1(nfc.ReadFile(MRTDFileIdDG1))
	if err != nil {
		return err
	}

	// TODO - allow caller to specify if they want to skip the photo (DG2)?
	readDG2 := true
	if readDG2 {
		slog.Info("Read EF.DG2")
		doc.Dg2, err = NewDG2(nfc.ReadFile(MRTDFileIdDG2))
		if err != nil {
			return err
		}
	}

	slog.Info("Read EF.DG7")
	doc.Dg7, err = NewDG7(nfc.ReadFile(MRTDFileIdDG7))
	if err != nil {
		return err
	}

	slog.Info("Read EF.DG11")
	doc.Dg11, err = NewDG11(nfc.ReadFile(MRTDFileIdDG11))
	if err != nil {
		return err
	}

	slog.Info("Read EF.DG12")
	doc.Dg12, err = NewDG12(nfc.ReadFile(MRTDFileIdDG12))
	if err != nil {
		return err
	}

	slog.Info("Read EF.DG13")
	doc.Dg13, err = NewDG13(nfc.ReadFile(MRTDFileIdDG13))
	if err != nil {
		return err
	}

	slog.Info("Read EF.DG14")
	doc.Dg14, err = NewDG14(nfc.ReadFile(MRTDFileIdDG14))
	if err != nil {
		return err
	}

	slog.Info("Read EF.DG15")
	doc.Dg15, err = NewDG15(nfc.ReadFile(MRTDFileIdDG15))
	if err != nil {
		return err
	}

	slog.Info("Read EF.DG16")
	doc.Dg16, err = NewDG16(nfc.ReadFile(MRTDFileIdDG16))
	if err != nil {
		return err
	}

	return nil
}

// NB returns partial data (MrtdDocument) in the event of an error
func ReadDocument(transceiver Transceiver, password *Password) (doc *Document, err error) {
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

	var nfc *NfcSession = NewNfcSession(transceiver)

	doc = new(Document)

	// NB spec recommends not to use, but iOS may pre-select the MRTD AID
	slog.Info("Selecting MF")
	if err = nfc.SelectMF(); err != nil {
		return doc, err
	}

	// TODO - EF.ATR/INFO? may contain extended length info

	slog.Info("Read EF.DIR")
	doc.Dir = NewEFDIR(nfc.ReadFile(MRTDFileIdEFDIR))
	if doc.Dir != nil {
		slog.Debug("EF.DIR", "bytes", doc.Dir.RawData)
	}

	slog.Info("Read CardAccess")

	// TODO - may not be present (OR may be present but not have PACE info)
	if doc.CardAccess, err = NewCardAccess(nfc.ReadFile(MRTDFileIdCardAccess)); err != nil {
		return doc, err
	}
	if doc.CardAccess != nil {
		slog.Debug("CardAccess", "bytes", doc.CardAccess.RawData)
		slog.Debug("CardAccess", "tlv", TlvDecode(doc.CardAccess.RawData))
		slog.Debug("CardAccess", "sec-infos", doc.CardAccess.SecurityInfos)
	}

	/*
	 * PACE
	 */
	// TODO - should we have an option to skip PACE
	{
		err = NewPace().DoPACE(nfc, password, doc)
		if err != nil {
			return doc, err
		}

		if nfc.sm != nil {
			slog.Debug("PACE", "sm", nfc.sm)
		}
	}

	slog.Info("Selecting MRTD AID")
	_, err = nfc.SelectAid(HexToBytes(MRTD_AID))
	if err != nil {
		return doc, err
	}

	/*
	 * Basic Access Control (BAC) - if required
	 */

	// NB we only attempt BAC if we don't already have SecureMessaging (i.e. via PACE)
	if nfc.sm == nil {
		err = NewBAC().DoBAC(nfc, password)
		if err != nil {
			return doc, err
		}

		if nfc.sm != nil {
			slog.Debug("BAC", "sm", nfc.sm)
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
	 */

	if doc.ChipAuthStatus == CHIP_AUTH_STATUS_NA {
		DoChipAuth(nfc, doc)
	}

	if doc.ChipAuthStatus == CHIP_AUTH_STATUS_NA {
		DoActiveAuth(nfc, doc)
	}

	slog.Info("** FINISHED **", "ChipAuthStatus", doc.ChipAuthStatus)

	return
}
