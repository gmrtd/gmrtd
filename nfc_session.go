package gmrtd

import (
	"bytes"
	"fmt"
	"log"
	"log/slog"
	"time"
)

const INS_EXTERNAL_AUTHENTICATE = byte(0x82)
const INS_GET_CHALLENGE = byte(0x84)
const INS_GENERAL_AUTHENTICATE = byte(0x86)
const INS_SELECT = byte(0xA4)
const INS_READ_BINARY = byte(0xB0)

// https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands/

// https: //web.archive.org/web/20090630004017/http://cheef.ru/docs/HowTo/APDU.info

// TODO - extended length support?
//
// 3.5.2 READ BINARY
// The support of the READ BINARY command with an odd INS byte by an eMRTD is CONDITIONAL. The eMRTD
// SHALL support this command variant if it supports data groups with 32 768 bytes or more.

// TODO - review and align with 9303 p10.. 3.6 Command Formats and Parameter Options (LDS1 and LDS2)

type NfcSession struct {
	transceiver Transceiver
	sm          *SecureMessaging
	maxLe       int

	// TODO
	apduLog []ApduLog
}

func NewNfcSession(transceiver Transceiver) *NfcSession {
	var nfc NfcSession
	nfc.transceiver = transceiver
	nfc.maxLe = 256
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

	slog.Debug("GetChallenge", "challenge", BytesToHex(rapdu.Data))

	return rapdu.Data, nil
}

func (nfc *NfcSession) ExternalAuthenticate(data []byte, le int) (out []byte, err error) {
	slog.Debug("ExternalAuthenticate", "data", BytesToHex(data), "le", le)

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

	slog.Debug("ExternalAuthenticate", "out", BytesToHex(rapdu.Data))

	return rapdu.Data, nil
}

func GeneralAuthenticate(nfc *NfcSession, commandChaining bool, data []byte) *RApdu {
	slog.Debug("GeneralAuthenticate", "cmdChaining", commandChaining, "data", BytesToHex(data))

	// TODO - use const
	cla := 0x00
	if commandChaining {
		cla = 0x10
	}

	cApdu := NewCApdu(byte(cla), INS_GENERAL_AUTHENTICATE, 0x00, 0x00, data, nfc.maxLe)

	rApdu, err := nfc.DoAPDU(cApdu, "General Authenticate")
	if err != nil {
		log.Panicf("DoAPDU error: %s", err)
	}

	slog.Debug("GeneralAuthenticate", "rApdu", rApdu.String())

	return rApdu
}

// TODO - why not just try to directly select file from MF?
//
//	0 0 0 0 1 0 0 0	– Select from MF (data field=path without the identifier of the MF)
func (nfc *NfcSession) SelectMF() (err error) {
	slog.Debug("SelectMF")

	//If P1-P2=’0000′ and if the data field is empty or equal to ‘3F00’, then select the MF.
	// https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands/

	// TODO - as per spec, but specify 3F00 (MF)?
	var capdu *CApdu = NewCApdu(0x00, INS_SELECT, 0x00, 0x0C, []byte{0x3f, 0x00}, 0)

	rapdu, err := nfc.DoAPDU(capdu, "Select MF")
	if err != nil {
		return err
	}

	if !rapdu.IsSuccess() {
		// TODO - AT/DE passports were giving 6700 response error.. so we'll tolerate this (at least for now)
		//if rapdu.Status == 0x6700 {
		//	return nil
		//}

		return fmt.Errorf("[SelectMF] Status:%x", rapdu.Status)
	}

	return nil
}

// returns: false if file-not-found, otherwise true
// TODO - why not force fileId to uint16?
func (nfc *NfcSession) SelectEF(fileId int) (selected bool, err error) {
	slog.Debug("SelectEF", "fileId", fileId)

	var capdu *CApdu = NewCApdu(0x00, INS_SELECT, 0x02, 0x0C, UInt16ToBytes(uint16(fileId)), 0)

	var rApdu *RApdu

	rApdu, err = nfc.DoAPDU(capdu, fmt.Sprintf("Select EF (fileId:%04x)", fileId))
	if err != nil {
		return false, err
	}

	if !rApdu.IsSuccess() {
		if rApdu.FileNotFound() {
			return false, nil
		} else if rApdu.Status == 0x6283 {
			// TODO - MY passport issue with card.access file
			return false, nil
		} else {
			return false, fmt.Errorf("[SelectEF] Status:%x", rApdu.Status)
		}
	}

	return true, nil
}

func (nfc *NfcSession) SelectAid(aid []byte) (selected bool, err error) {
	slog.Debug("SelectAid", "aid", BytesToHex(aid))

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
func (nfc *NfcSession) ReadFile(fileId int) (fileData []byte) {
	slog.Debug("ReadFile", "fileId", fileData)

	// TODO - read (without select) using short-EF is mandatory for MRTD (p10-page-18).. so maybe better to do this rather than selecting the file first
	//			- although having problems getting it to work

	sel, err := nfc.SelectEF(fileId)
	if err != nil {
		log.Panicf("SelectEF error: %s", err)
	}
	if !sel {
		// file not found
		return nil
	}

	var fileBuf *bytes.Buffer = new(bytes.Buffer)

	{
		// read first 4 bytes from file
		fileHeader := nfc.ReadBinaryFromOffset(0, 4)
		fileBuf.Write(fileHeader)

		var totalBytes int
		{
			// extract length (of parent tag) to determine file size
			tmpBuf := bytes.NewBuffer(fileHeader)
			TlvGetTag(tmpBuf)
			totalBytes = TlvGetLength(tmpBuf)
			totalBytes += 4 - tmpBuf.Len()
		}

		// read remainder of file
		if fileBuf.Len() < totalBytes {
			maxReadAmount := nfc.maxLe

			for {
				bytesToRead := totalBytes - fileBuf.Len()
				if bytesToRead > maxReadAmount {
					bytesToRead = maxReadAmount
				}

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
	}

	return
}

type ApduLog struct {
	Desc  string
	Tx    []byte
	Rx    []byte
	Child *ApduLog // optional (e.g. if secure-messaging enabled)
	DurMs int
}

// TODO (OSWALD) accept 'desc' for logging context.. add also to doTransceive
func (nfc *NfcSession) DoAPDU(cApdu *CApdu, desc string) (rApdu *RApdu, err error) {
	var apduLog *ApduLog

	if nfc.sm == nil {
		rApdu, apduLog, err = nfc.doTransceive(cApdu, desc)
	} else {
		apduLog = new(ApduLog)

		apduLog.Desc = desc
		apduLog.Tx = bytes.Clone(cApdu.Encode())

		startTime := time.Now()

		{
			var encCApdu *CApdu
			if encCApdu, err = nfc.sm.Encode(cApdu, uint64(nfc.maxLe)); err != nil {
				return nil, err
			}

			var encRApdu *RApdu
			encRApdu, apduLog.Child, err = nfc.doTransceive(encCApdu, desc)
			if err != nil {
				return nil, err
			}

			rApdu, err = nfc.sm.Decode(encRApdu.Encode())
			if err != nil {
				return nil, err
			}
		}

		endTime := time.Now()

		apduLog.DurMs = int(endTime.Sub(startTime).Milliseconds())

		apduLog.Rx = bytes.Clone(rApdu.Encode())
	}

	// record the APDU log
	nfc.recordApduLog(*apduLog)

	return rApdu, err
}

func (nfc *NfcSession) doTransceive(cApdu *CApdu, desc string) (rApdu *RApdu, apduLog *ApduLog, err error) {
	apduLog = new(ApduLog)

	apduLog.Desc = desc
	apduLog.Tx = bytes.Clone(cApdu.Encode())

	startTime := time.Now()
	rApduBytes := nfc.transceiver.Transceive(cApdu.Encode())
	endTime := time.Now()

	apduLog.DurMs = int(endTime.Sub(startTime).Milliseconds())

	apduLog.Rx = bytes.Clone(rApduBytes)

	rApdu, err = ParseRApdu(rApduBytes)

	return
}

func (nfc *NfcSession) recordApduLog(log ApduLog) {
	nfc.apduLog = append(nfc.apduLog, log)
}
