package iso7816

import (
	"bytes"
	"fmt"
	"log"
	"log/slog"
	"time"

	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

const INS_MANAGE_SE = byte(0x22)
const INS_EXTERNAL_AUTHENTICATE = byte(0x82)
const INS_GET_CHALLENGE = byte(0x84)
const INS_GENERAL_AUTHENTICATE = byte(0x86)
const INS_INTERNAL_AUTHENTICATE = byte(0x88)
const INS_SELECT = byte(0xA4)
const INS_READ_BINARY = byte(0xB0)

// TODO - extended length support? odd INS read-binary can support larger offset.. and potentially avoid SELECT FILE
//
// 3.5.2 READ BINARY
// The support of the READ BINARY command with an odd INS byte by an eMRTD is CONDITIONAL. The eMRTD
// SHALL support this command variant if it supports data groups with 32 768 bytes or more.

// TODO - review and align with 9303 p10.. 3.6 Command Formats and Parameter Options (LDS1 and LDS2)

type NfcSession struct {
	transceiver Transceiver
	SM          *SecureMessaging
	MaxLe       int
	ApduLog     []ApduLog
}

func NewNfcSession(transceiver Transceiver) *NfcSession {
	var nfc NfcSession
	nfc.transceiver = transceiver
	nfc.MaxLe = 256
	return &nfc
}

func (nfc *NfcSession) GetChallenge(length int) (out []byte, err error) {
	slog.Debug("GetChallenge", "length", length)

	rapdu, err := nfc.DoAPDU(NewCApdu(0x00, INS_GET_CHALLENGE, 0x00, 0x00, nil, length), "Get Challenge")
	if err != nil {
		return nil, err
	}

	if !rapdu.IsSuccess() {
		return nil, fmt.Errorf("[GetChallenge] Status:%x", rapdu.Status)
	}

	if len(rapdu.Data) != length {
		return nil, fmt.Errorf("[GetChallenge] Incorrect length (exp:%d, act:%d)", length, len(rapdu.Data))
	}

	slog.Debug("GetChallenge", "challenge", utils.BytesToHex(rapdu.Data))

	return rapdu.Data, nil
}

func (nfc *NfcSession) ExternalAuthenticate(data []byte, le int) (out []byte, err error) {
	slog.Debug("ExternalAuthenticate", "data", utils.BytesToHex(data), "le", le)

	rapdu, err := nfc.DoAPDU(NewCApdu(0x00, INS_EXTERNAL_AUTHENTICATE, 0x00, 0x00, data, le), "External Authenticate")
	if err != nil {
		return nil, err
	}

	if !rapdu.IsSuccess() {
		return nil, fmt.Errorf("[ExternalAuthenticate] Status:%x", rapdu.Status)
	}

	if len(rapdu.Data) != le {
		return nil, fmt.Errorf("[ExternalAuthenticate] Incorrect length (exp:%d, act:%d)", le, len(rapdu.Data))
	}

	slog.Debug("ExternalAuthenticate", "out", utils.BytesToHex(rapdu.Data))

	return rapdu.Data, nil
}

func (nfc *NfcSession) GeneralAuthenticate(commandChaining bool, data []byte) *RApdu {
	slog.Debug("GeneralAuthenticate", "cmdChaining", commandChaining, "data", utils.BytesToHex(data))

	cla := 0x00
	if commandChaining {
		cla = 0x10
	}

	cApdu := NewCApdu(byte(cla), INS_GENERAL_AUTHENTICATE, 0x00, 0x00, data, nfc.MaxLe)

	rApdu, err := nfc.DoAPDU(cApdu, "General Authenticate")
	if err != nil {
		log.Panicf("DoAPDU error: %s", err)
	}

	slog.Debug("GeneralAuthenticate", "rApdu", rApdu.String())

	return rApdu
}

// TODO - seems the same as SetAT?
func (nfc *NfcSession) MseSetKAT(p1 uint8, p2 uint8, data []byte) (err error) {
	return nfc.MseSetAT(p1, p2, data)
}

func (nfc *NfcSession) MseSetAT(p1 uint8, p2 uint8, data []byte) (err error) {
	cApdu := NewCApdu(0x00, INS_MANAGE_SE, p1, p2, data, 0)

	var rApdu *RApdu
	rApdu, err = nfc.DoAPDU(cApdu, fmt.Sprintf("MSE:Set AT (p1:%02x,p2:%02x)", p1, p2))
	if err != nil {
		return err
	}
	if !rApdu.IsSuccess() {
		return fmt.Errorf("MSE:Set AT failed (Status:%x)", rApdu.Status)
	}

	return nil
}

// 0 0 0 0 1 0 0 0	– Select from MF (data field=path without the identifier of the MF)
func (nfc *NfcSession) SelectMF() (err error) {
	slog.Debug("SelectMF")

	// NB as per 9303 specs, but explicitly specifying MF (x3f00)
	//	  - If P1-P2=’0000′ and if the data field is empty or equal to ‘3F00’, then select the MF.
	//      https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands/

	var capdu *CApdu = NewCApdu(0x00, INS_SELECT, 0x00, 0x0C, []byte{0x3f, 0x00}, 0)

	rapdu, err := nfc.DoAPDU(capdu, "Select MF")
	if err != nil {
		return err
	}

	if !rapdu.IsSuccess() {
		if rapdu.Status == RAPDU_SECURITY_CONDITION_NOT_SATIFIED {
			// NB observed for NZ passport - silently tolerate
			return nil
		} else if rapdu.Status == RAPDU_STATUS_FUNCTION_NOT_SUPPORTED {
			// NB observed for CN passport - silently tolerate
			return nil
		} else if rapdu.Status == RAPDU_STATUS_INCORRECT_P1_OR_P2_PARAMETER {
			// NB observed for AU passport - silently tolerate
			// TODO - could be an indicator that we should support other variants also for select-MF
			return nil
		} else {
			return fmt.Errorf("[SelectMF] Status:%x", rapdu.Status)
		}
	}

	return nil
}

// returns: false if file-not-found, otherwise true
func (nfc *NfcSession) SelectEF(fileId uint16) (selected bool, err error) {
	slog.Debug("SelectEF", "fileId", fileId)

	var capdu *CApdu = NewCApdu(0x00, INS_SELECT, 0x02, 0x0C, utils.UInt16ToBytes(fileId), 0)

	var rApdu *RApdu

	rApdu, err = nfc.DoAPDU(capdu, fmt.Sprintf("Select EF (fileId:%04x)", fileId))
	if err != nil {
		return false, err
	}

	if !rApdu.IsSuccess() {
		if rApdu.FileNotFound() {
			return false, nil
		} else if rApdu.Status == RAPDU_STATUS_SELECTED_FILE_INVALIDATED {
			// NB we've seen this with a Malaysia passport when selecting card.access before BAC
			return false, nil
		} else {
			return false, fmt.Errorf("[SelectEF] Status:%x", rApdu.Status)
		}
	}

	return true, nil
}

func (nfc *NfcSession) SelectAid(aid []byte) (selected bool, err error) {
	slog.Debug("SelectAid", "aid", utils.BytesToHex(aid))

	rApdu, err := nfc.DoAPDU(NewCApdu(0x00, INS_SELECT, 0x04, 0x0C, aid, 0), fmt.Sprintf("Select AID (%x)", aid))
	if err != nil {
		return false, err
	}

	// TODO - may want to pass status back to caller as error may be tolerated
	if !rApdu.IsSuccess() {
		if rApdu.FileNotFound() {
			return false, nil
		} else {
			return false, fmt.Errorf("[SelectAid] Status:%x, AID:%x", rApdu.Status, aid)
		}
	}

	return true, nil
}

// NB may not return requested length
func (nfc *NfcSession) ReadBinaryFromOffset(offset int, length int) []byte {
	slog.Debug("ReadBinaryFromOffset", "offset", offset, "length", length)

	var capdu *CApdu = NewCApdu(0x00, INS_READ_BINARY, byte(offset/256), byte(offset%256), nil, length)

	rapdu, err := nfc.DoAPDU(capdu, fmt.Sprintf("Read Binary (offset:%d, length:%d)", offset, length))
	if err != nil {
		log.Panicf("DoAPDU error: %s", err)
	}

	if !rapdu.IsSuccess() {
		log.Panicf("[ReadBinaryFromOffset] Status:%x", rapdu.Status)
	}

	out := rapdu.Data

	return out
}

// returns: file contents OR nil if file not found
func (nfc *NfcSession) ReadFile(fileId uint16) (fileData []byte) {
	slog.Debug("ReadFile", "fileId", fileId)

	sel, err := nfc.SelectEF(fileId)
	if err != nil {
		log.Panicf("SelectEF error: %s", err)
	}
	if !sel {
		// file not found
		return nil
	}

	var fileBuf *bytes.Buffer = new(bytes.Buffer)

	// read first 4 bytes from file
	fileHeader := nfc.ReadBinaryFromOffset(0, 4)
	fileBuf.Write(fileHeader)

	var totalBytes int
	{
		// extract length (of parent tag) to determine file size
		tmpBuf := bytes.NewBuffer(fileHeader)
		tlv.GetTag(tmpBuf)
		totalBytes = int(tlv.GetLength(tmpBuf))
		totalBytes += 4 - tmpBuf.Len()
	}

	// read remainder of file
	if fileBuf.Len() < totalBytes {
		maxReadAmount := nfc.MaxLe

		for {
			bytesToRead := min(maxReadAmount, totalBytes-fileBuf.Len())

			tmpData := nfc.ReadBinaryFromOffset(fileBuf.Len(), bytesToRead)

			// sanity check that we received some data
			// TODO - we've seen issues with jmrtd applet where it returns 0 bytes if we ask for 236 bytes of data...
			//			... may want to try dropping the requested read amount in this scenario.. and retrying
			if len(tmpData) < 1 {
				log.Panicf("[ReadFile] Didn't receive any data")
			}

			fileBuf.Write(tmpData)

			if fileBuf.Len() >= totalBytes {
				break
			}
		}

		fileData = bytes.Clone(fileBuf.Bytes())

		if len(fileData) != totalBytes {
			log.Panicf("Data read differs to expected length (exp:%d, act:%d)", totalBytes, len(fileData))
		}
	}

	slog.Debug("ReadFile", "fileId", fileId, "data", utils.BytesToHex(fileData))

	return fileData
}

type ApduLog struct {
	Desc      string    `json:"desc,omitempty"`
	Tx        []byte    `json:"tx,omitempty"`
	Rx        []byte    `json:"rx,omitempty"`
	Child     *ApduLog  `json:"child,omitempty"` // optional (e.g. if secure-messaging enabled)
	DurMs     int       `json:"durMs,omitempty"`
	StartTime time.Time `json:"startTime,omitempty"`
}

// creates a new instance, records the desc/tx information and starts the timer
func NewApduLog(desc string, tx []byte) *ApduLog {
	var out ApduLog

	out.Desc = desc
	out.Tx = bytes.Clone(tx)

	out.StartTime = time.Now()

	return &out
}

// finalises an instance, records rx and calculates duration(ms)
func (apduLog *ApduLog) Finalise(rx []byte) {
	endTime := time.Now()

	apduLog.DurMs = int(endTime.Sub(apduLog.StartTime).Milliseconds())

	apduLog.Rx = bytes.Clone(rx)
}

func (nfc *NfcSession) DoAPDU(cApdu *CApdu, desc string) (rApdu *RApdu, err error) {
	var apduLog *ApduLog

	if nfc.SM == nil {
		rApdu, apduLog, err = nfc.doTransceive(cApdu, desc)
	} else {
		apduLog = NewApduLog(desc, cApdu.Encode())

		var encCApdu *CApdu
		if encCApdu, err = nfc.SM.Encode(cApdu); err != nil {
			return nil, err
		}

		var encRApdu *RApdu
		encRApdu, apduLog.Child, err = nfc.doTransceive(encCApdu, desc)
		if err != nil {
			return nil, err
		}

		rApdu, err = nfc.SM.Decode(encRApdu.Encode())
		if err != nil {
			return nil, err
		}

		apduLog.Finalise(rApdu.Encode())
	}

	// record the APDU log
	nfc.recordApduLog(*apduLog)

	return rApdu, err
}

func (nfc *NfcSession) doTransceive(cApdu *CApdu, desc string) (rApdu *RApdu, apduLog *ApduLog, err error) {
	cApduBytes := cApdu.Encode()

	apduLog = NewApduLog(desc, cApduBytes)

	rApduBytes := nfc.transceiver.Transceive(int(cApdu.cla), int(cApdu.ins), int(cApdu.p1), int(cApdu.p2), cApdu.data, cApdu.le, cApduBytes)

	apduLog.Finalise(rApduBytes)

	rApdu, err = ParseRApdu(rApduBytes)

	return
}

func (nfc *NfcSession) recordApduLog(log ApduLog) {
	nfc.ApduLog = append(nfc.ApduLog, log)
}
