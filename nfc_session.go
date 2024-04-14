package gmrtd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
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

// TODO - look at using 'short-file' id's

type NfcSession struct {
	transceiver Transceiver
	sm          *SecureMessaging
	maxLe       int
}

func NewNfcSession(transceiver Transceiver) *NfcSession {
	var nfc NfcSession
	nfc.transceiver = transceiver
	nfc.maxLe = 256
	return &nfc
}

func (nfc *NfcSession) GetChallenge(length int) (out []byte, err error) {
	rapdu, err := nfc.DoAPDU(NewCApdu(0x00, INS_GET_CHALLENGE, 0x00, 0x00, nil, length))
	if err != nil {
		return nil, err
	}

	if !rapdu.IsSuccess() {
		return nil, fmt.Errorf("[GetChallenge] Status:%x", rapdu.Status)
	}

	if len(rapdu.Data) != length {
		return nil, fmt.Errorf("[GetChallenge] Incorrect length (exp:%d, act:%d)", length, len(rapdu.Data))
	}

	return rapdu.Data, nil
}

func (nfc *NfcSession) ExternalAuthenticate(data []byte, le int) (out []byte, err error) {
	rapdu, err := nfc.DoAPDU(NewCApdu(0x00, INS_EXTERNAL_AUTHENTICATE, 0x00, 0x00, data, le))
	if err != nil {
		return nil, err
	}

	if !rapdu.IsSuccess() {
		return nil, fmt.Errorf("[ExternalAuthenticate] Status:%x", rapdu.Status)
	}

	if len(rapdu.Data) != le {
		return nil, fmt.Errorf("[ExternalAuthenticate] Incorrect length (exp:%d, act:%d)", le, len(rapdu.Data))
	}

	return rapdu.Data, nil
}

func GeneralAuthenticate(nfc *NfcSession, commandChaining bool, data []byte) *RApdu {
	// TODO - use const
	cla := 0x00
	if commandChaining {
		cla = 0x10
	}

	cApdu := NewCApdu(byte(cla), INS_GENERAL_AUTHENTICATE, 0x00, 0x00, data, nfc.maxLe)

	rApdu, err := nfc.DoAPDU(cApdu)
	if err != nil {
		log.Panicf("TODO")
	}

	return rApdu
}

// TODO - why not just try to directly select file from MF?
//
//	0 0 0 0 1 0 0 0	– Select from MF (data field=path without the identifier of the MF)
func (nfc *NfcSession) SelectMF() (err error) {
	//If P1-P2=’0000′ and if the data field is empty or equal to ‘3F00’, then select the MF.
	// https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands/
	var capdu *CApdu = NewCApdu(0x00, INS_SELECT, 0x00, 0x00, []byte{0x3f, 0x00}, 0) // TODO - P2 was 0C

	rapdu, err := nfc.DoAPDU(capdu)
	if err != nil {
		return err
	}

	if !rapdu.IsSuccess() {
		// TODO - AT/DE passports were giving 6700 response error.. so we'll tolerate this (at least for now)
		if rapdu.Status == 0x6700 {
			return nil
		}

		return fmt.Errorf("[SelectMF] Status:%x", rapdu.Status)
	}

	return nil
}

// returns: false if file-not-found, otherwise true
func (nfc *NfcSession) SelectEF(fileId int) (selected bool, err error) {
	fileIdBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(fileIdBytes, uint16(fileId))
	var capdu *CApdu = NewCApdu(0x00, INS_SELECT, 0x02, 0x0C, fileIdBytes, 0)

	var rApdu *RApdu

	rApdu, err = nfc.DoAPDU(capdu)
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
	rapdu, err := nfc.DoAPDU(NewCApdu(0x00, INS_SELECT, 0x04, 0x0C, aid, 0))
	if err != nil {
		return false, err
	}

	// TODO - may want to pass status back to caller as error may be tolerated
	if !rapdu.IsSuccess() {
		return false, fmt.Errorf("[SelectAid] Status:%x, AID:%x", rapdu.Status, aid)
	}

	return true, nil
}

// NB may not return requested length
func (nfc *NfcSession) ReadBinaryFromOffset(offset int, length int) []byte {
	var capdu *CApdu = NewCApdu(0x00, INS_READ_BINARY, byte(offset/256), byte(offset%256), nil, length)

	rapdu, err := nfc.DoAPDU(capdu)
	if err != nil {
		log.Panicf("TODO")
	}

	if !rapdu.IsSuccess() {
		log.Panicf("[ReadBinaryFromOffset] Status:%x", rapdu.Status)
	}

	out := rapdu.Data

	return out
}

// returns: file contents OR nil if file not found
func (nfc *NfcSession) ReadFile(fileId int) (fileData []byte) {

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

func (nfc *NfcSession) DoAPDU(capdu *CApdu) (rapdu *RApdu, err error) {
	var capduBytes []byte

	if nfc.sm == nil {
		capduBytes = capdu.Encode()
	} else {
		var enccapdu *CApdu

		if enccapdu, err = nfc.sm.Encode(capdu, uint64(nfc.maxLe)); err != nil {
			return nil, err
		}

		capduBytes = enccapdu.Encode()
	}

	rapduBytes := nfc.transceiver.Transceive(capduBytes)

	if nfc.sm != nil {
		rapdu, err = nfc.sm.Decode(rapduBytes)
	} else {
		rapdu, err = ParseRApdu(rapduBytes)
	}

	return rapdu, err
}
