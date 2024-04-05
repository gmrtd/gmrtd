package gmrtd

import (
	"bytes"
	"encoding/binary"
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

func (nfc *NfcSession) GetChallenge(length int) []byte {
	rapdu := nfc.DoAPDU(NewCApdu(0x00, INS_GET_CHALLENGE, 0x00, 0x00, nil, length))

	if !rapdu.IsSuccess() {
		log.Panicf("[GetChallenge] Status:%x", rapdu.Status)
	}

	VerifyByteLength(rapdu.Data, length)

	return rapdu.Data
}

func (nfc *NfcSession) ExternalAuthenticate(data []byte, le int) []byte {
	rapdu := nfc.DoAPDU(NewCApdu(0x00, INS_EXTERNAL_AUTHENTICATE, 0x00, 0x00, data, le))

	if !rapdu.IsSuccess() {
		log.Panicf("[ExternalAuthenticate] Status:%x", rapdu.Status)
	}

	VerifyByteLength(rapdu.Data, le)

	return rapdu.Data
}

func GeneralAuthenticate(nfc *NfcSession, commandChaining bool, data []byte) *RApdu {
	// TODO - use const
	cla := 0x00
	if commandChaining {
		cla = 0x10
	}

	cApdu := NewCApdu(byte(cla), INS_GENERAL_AUTHENTICATE, 0x00, 0x00, data, nfc.maxLe)

	return nfc.DoAPDU(cApdu)
}

// TODO - why not just try to directly select file from MF?
//
//	0 0 0 0 1 0 0 0	– Select from MF (data field=path without the identifier of the MF)
func (nfc *NfcSession) SelectMF() {
	//If P1-P2=’0000′ and if the data field is empty or equal to ‘3F00’, then select the MF.
	// https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands/
	var capdu *CApdu = NewCApdu(0x00, INS_SELECT, 0x00, 0x00, []byte{0x3f, 0x00}, 0) // TODO - P2 was 0C
	rapdu := nfc.DoAPDU(capdu)
	if !rapdu.IsSuccess() {
		// TODO - AT/DE passports were giving 6700 response error.. so we'll tolerate this (at least for now)
		if rapdu.Status == 0x6700 {
			return
		}

		log.Panicf("[SelectMF] Status:%x", rapdu.Status)
	}
}

// returns: false if file-not-found, otherwise true
func (nfc *NfcSession) SelectEF(fileId int) bool {
	fileIdBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(fileIdBytes, uint16(fileId))
	var capdu *CApdu = NewCApdu(0x00, INS_SELECT, 0x02, 0x0C, fileIdBytes, 0)
	rapdu := nfc.DoAPDU(capdu)
	if !rapdu.IsSuccess() {
		if rapdu.FileNotFound() {
			return false
		} else if rapdu.Status == 0x6283 {
			// TODO - MY passport issue with card.access file
			return false
		} else {
			log.Panicf("[SelectEF] Status:%x", rapdu.Status)
		}
	}

	return true
}

func (nfc *NfcSession) SelectAid(aid []byte) {
	rapdu := nfc.DoAPDU(NewCApdu(0x00, INS_SELECT, 0x04, 0x0C, aid, 0))
	// TODO - may want to pass status back to caller as error may be tolerated
	if !rapdu.IsSuccess() {
		log.Panicf("[SelectAid] Status:%x, AID:%x", rapdu.Status, aid)
	}
}

// NB may not return requested length
func (nfc *NfcSession) ReadBinaryFromOffset(offset int, length int) []byte {

	var capdu *CApdu = NewCApdu(0x00, INS_READ_BINARY, byte(offset/256), byte(offset%256), nil, length)
	rapdu := nfc.DoAPDU(capdu)
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

	if !nfc.SelectEF(fileId) {
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

func (nfc *NfcSession) DoAPDU(capdu *CApdu) *RApdu {
	var capduBytes []byte

	if nfc.sm == nil {
		capduBytes = capdu.Encode()
	} else {
		capduBytes = nfc.sm.Encode(capdu, uint64(nfc.maxLe)).Encode()
	}

	rapduBytes := nfc.transceiver.Transceive(capduBytes)

	var rapdu *RApdu
	if nfc.sm != nil {
		rapdu = nfc.sm.Decode(rapduBytes)
	} else {
		rapdu = ParseRApdu(rapduBytes)
	}

	return rapdu
}
