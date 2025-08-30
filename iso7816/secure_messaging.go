package iso7816

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/big"

	"github.com/aead/cmac"
	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

// SM Data Objects (see [ISO/IEC 7816-4])
// - not specific to MRTD, but from 7816-4

//9.8.4 Message Structure of SM APDUs
//The SM Data Objects (see [ISO/IEC 7816-4]) MUST be used in the following order:
//• Command APDU: [DO‘85’ or DO‘87’] [DO‘97’] DO‘8E’.
//• Response APDU: [DO‘85’ or DO‘87’] [DO‘99’] DO‘8E’.
//In case INS is even, DO‘87’ SHALL be used, and in case INS is odd, DO‘85’ SHALL be used.
//All SM Data Objects MUST be encoded in BER TLV as specified in [ISO/IEC 7816-4]. The command header MUST be
//included in the MAC calculation, therefore the class byte CLA = 0x0C MUST be used.
//The actual value of Lc will be modified to Lc’ after application of Secure Messaging. If required, an appropriate data
//object may optionally be included into the APDU data part in order to convey the original value of Lc.
//Figure 5 shows the transformation of an unprotected command APDU to a protected command APDU in the case Data
//and Le are available. If no Data is available, leave building DO ‘87’ out. If Le is not available, leave building DO ‘97’ out.
//To avoid ambiguity it is RECOMMENDED not to use an empty value field of Le Data Object (see also Section 10.4 of
//[ISO/IEC 7816-4]).
//Figure 6 shows the transformation of an unprotected response APDU to a protected response APDU in case Data is
//available. If no Data is available, leave building DO ‘87’ out.

const CLA_MASK byte = 0x0C

type SecureMessaging struct {
	alg       cryptoutils.BlockCipherAlg
	ksEnc     []byte
	ksMac     []byte
	ssc       []byte
	encCipher cipher.Block
	macCipher cipher.Block
}

func (sm1 SecureMessaging) Equal(sm2 SecureMessaging) bool {
	if (sm1.alg == sm2.alg) &&
		bytes.Equal(sm1.ksEnc, sm2.ksEnc) &&
		bytes.Equal(sm1.ksMac, sm2.ksMac) &&
		bytes.Equal(sm1.ssc, sm2.ssc) {
		return true
	}

	return false
}

func (sm SecureMessaging) GetKsEnc() []byte {
	return bytes.Clone(sm.ksEnc)
}

func NewSecureMessaging(alg cryptoutils.BlockCipherAlg, ksEnc []byte, ksMac []byte) (sm *SecureMessaging, err error) {
	sm = new(SecureMessaging)

	sm.alg = alg
	sm.ksEnc = ksEnc
	sm.ksMac = ksMac

	if sm.encCipher, err = cryptoutils.GetCipherForKey(sm.alg, ksEnc); err != nil {
		return nil, fmt.Errorf("(NewSecureMessaging) GetCipherForKey:ksEnc: %w", err)
	}

	if sm.macCipher, err = cryptoutils.GetCipherForKey(sm.alg, ksMac); err != nil {
		return nil, fmt.Errorf("(NewSecureMessaging) GetCipherForKey:ksMac: %w", err)
	}

	// init SSC (based on block size)
	// NB we use the encryption block-size as crypt/mac are always the same algorithm
	sm.ssc = make([]byte, sm.encCipher.BlockSize())

	slog.Debug("NewSecureMessaging", "SM", sm.String())

	return sm, nil
}

func (sm *SecureMessaging) SetSSC(ssc []byte) {
	if len(ssc) != len(sm.ssc) {
		panic(fmt.Sprintf("[SetSSC] length mismatch (exp:%d, act:%d)", len(sm.ssc), len(ssc)))
	}
	copy(sm.ssc, ssc)
	slog.Debug("SetSSC", "SSC", utils.BytesToHex(sm.ssc))
}

func (sm SecureMessaging) String() string {
	return fmt.Sprintf("(alg:%d, ksenc:%x, ksmac:%x, ssc:%x)", sm.alg, sm.ksEnc, sm.ksMac, sm.ssc)
}

// increments the SSC
func (sm *SecureMessaging) sscIncrement() {
	var sscPre *big.Int = new(big.Int).SetBytes(sm.ssc)
	var sscPost *big.Int = new(big.Int)

	sscPost.Add(sscPre, big.NewInt(1))

	if len(sscPost.Bytes()) > len(sm.ssc) {
		// handle overflow condition
		sm.ssc = make([]byte, len(sm.ssc))
	} else {
		sscPost.FillBytes(sm.ssc)
	}
}

func (sm *SecureMessaging) cbcCrypt(data []byte, encrypt bool) []byte {
	// create 0'd IV
	iv := make([]byte, sm.encCipher.BlockSize())

	// special IV setup for AES
	if sm.alg == cryptoutils.AES {
		// IV = K(KSenc,SSC)
		// Note: suppress secure mode and padding scheme warning in sonar
		//		 - this is required for setting up the IV for AES
		sm.encCipher.Encrypt(iv, sm.ssc) // NOSONAR
	}

	out := cryptoutils.CryptCBC(sm.encCipher, iv, data, encrypt)

	return out
}

// NB data must be padded to block boundary before calling
func (sm *SecureMessaging) generateMac(data []byte) (mac []byte, err error) {
	switch sm.alg {
	case cryptoutils.TDES:
		if mac, err = cryptoutils.ISO9797RetailMacDes(sm.ksMac, data); err != nil {
			return nil, err
		}
	case cryptoutils.AES:
		var err error
		// CMAC-mode with MAC length of 8 bytes
		// AES [FIPS 197] SHALL be used in CMAC-mode [SP 800-38B] with a MAC length of 8 bytes.
		mac, err = cmac.Sum(data, sm.macCipher, 8)
		if err != nil {
			return nil, fmt.Errorf("unable to generate Auth-Token (CMAC): %s", err)
		}
	}

	//slog.Debug("GenerateMac", "Data", BytesToHex(data), "MAC", BytesToHex(mac))

	return mac, nil
}

func (sm *SecureMessaging) cryptoPad(data []byte) []byte {
	// NB we use the encryption block-size as crypt/mac are always the same algorithm
	return cryptoutils.ISO9797Method2Pad(data, sm.encCipher.BlockSize())
}

// NB fails if empty data passed in (as doesn't qualify the padding rules)
func (sm *SecureMessaging) cryptoUnpad(data []byte) []byte {
	data, err := cryptoutils.ISO9797Method2Unpad(data)
	if err != nil {
		panic(fmt.Sprintf("[cryptoUnpad] ISO9797Method2Unpad error: %s", err))
	}

	return data
}

// builds tag 85/87 (depending on Ins)
// adds the tag (if any) to 'nodes'
func (sm *SecureMessaging) buildTag85or87(cApdu *CApdu, nodes *tlv.TlvNodes) {
	if cApdu.HaveData() {
		var tag tlv.TlvTag
		if cApdu.ins%2 == 0 {
			tag = 0x87
		} else {
			tag = 0x85
		}

		value := []byte{0x01}
		value = append(value, sm.cbcCrypt(sm.cryptoPad(cApdu.data), true)...)

		nodes.AddNode(tlv.NewTlvSimpleNode(tlv.TlvTag(tag), value))
	}
}

// builds tag 97 (depending on presence of Le)
// adds the tag (if any) to 'nodes'
func (sm *SecureMessaging) buildTag97(cApdu *CApdu, nodes *tlv.TlvNodes) {
	if cApdu.HaveLe() {
		nodes.AddNode(tlv.NewTlvSimpleNode(tlv.TlvTag(0x97), cApdu.EncodeLe()))
	}
}

// builds tag 85
// adds the tag to 'nodes'
func (sm *SecureMessaging) buildTag8E(cApdu *CApdu, nodes *tlv.TlvNodes) (err error) {
	// cmdHeader
	var cmdHeaderPadded []byte = sm.cryptoPad(cApdu.EncodeHeader())
	// mask CLA
	if len(cmdHeaderPadded) < 1 {
		return fmt.Errorf("[buildTag8E] cmdHeaderPadded must have more than 0 bytes")
	}
	cmdHeaderPadded[0] = CLA_MASK

	macData := make([]byte, 0)
	macData = append(macData, sm.ssc...)
	macData = append(macData, cmdHeaderPadded...)
	macData = append(macData, nodes.Encode()...)

	var mac []byte
	if mac, err = sm.generateMac(sm.cryptoPad(macData)); err != nil {
		return fmt.Errorf("[buildTag8E] generateMac error: %w", err)
	}

	nodes.AddNode(tlv.NewTlvSimpleNode(tlv.TlvTag(0x8E), mac))

	return nil
}

// calculate the secure-messaging cApdu Le
// LE should always be 256 or 65536 for secure-messaging
// NB 256->0x00, 65536->0x0000 when LE is encoded
func calcSmLe(cApdu *CApdu) int {
	var smLe int = 256
	if cApdu.IsExtended() {
		smLe = 65536
	}

	return smLe
}

func (sm *SecureMessaging) Encode(cApdu *CApdu) (out *CApdu, err error) {
	// 9303p11 - page 63 (Message Structure of SM APDUs)

	slog.Debug("Encode", "SM(pre)", sm.String())

	if cApdu == nil {
		return nil, fmt.Errorf("CAPDU missing")
	}

	// increment SSC
	sm.sscIncrement()

	nodes := tlv.NewTlvNodes()

	// do85/do87
	sm.buildTag85or87(cApdu, nodes)

	// do97
	sm.buildTag97(cApdu, nodes)

	// do8E
	err = sm.buildTag8E(cApdu, nodes)
	if err != nil {
		return nil, err
	}

	out = NewCApdu(CLA_MASK, cApdu.ins, cApdu.p1, cApdu.p2, nodes.Encode(), calcSmLe(cApdu))

	slog.Debug("Encode", "In", cApdu.String(), "Out", out.String(), "Out(bytes)", utils.BytesToHex(out.Encode()))

	return out, nil
}

// generates the mac data (ie data to be mac'd) for the specified SM rApdu TLV
func generateMacDataForSmRApduTlv(smRApduTlv *tlv.TlvNodes, ssc []byte) []byte {
	out := make([]byte, 0)
	out = append(out, ssc...)
	out = append(out, smRApduTlv.GetNode(0x85).Encode()...)
	out = append(out, smRApduTlv.GetNode(0x87).Encode()...)
	out = append(out, smRApduTlv.GetNode(0x99).Encode()...)
	return out
}

func (sm *SecureMessaging) decodeVerifyMAC(tlv *tlv.TlvNodes) error {
	macData := generateMacDataForSmRApduTlv(tlv, sm.ssc)
	actMAC := tlv.GetNode(0x8E).GetValue()

	expMAC, err := sm.generateMac(sm.cryptoPad(macData))
	if err != nil {
		return fmt.Errorf("(sm.decodeVerifyMAC) generateMac error: %w", err)
	}

	if !bytes.Equal(expMAC, actMAC) {
		slog.Debug("sm.decodeVerifyMAC: MAC mismatch", "Exp", utils.BytesToHex(expMAC), "Act", utils.BytesToHex(actMAC))
		return fmt.Errorf("(sm.decodeVerifyMAC) MAC mismatch (Exp: %x) (Act: %x)", expMAC, actMAC)
	}

	return nil
}

func (sm *SecureMessaging) decodeSmRApduData(encodedData []byte) (out []byte, err error) {
	tmpBytes := bytes.Clone(encodedData)

	// field has a leading 'version' byte that needs to be removed (if field is present)

	// verify that 'verison' is 0x01 before removing
	if tmpBytes[0] != 0x01 {
		return nil, fmt.Errorf("(sm.decodeSmRApduData) version not set to 0x01")
	}

	// remove the leading 'version' byte
	tmpBytes = tmpBytes[1:]

	out = sm.cryptoUnpad(sm.cbcCrypt(tmpBytes, false))

	return out, nil
}

func (sm *SecureMessaging) Decode(rApduBytes []byte) (rApdu *RApdu, err error) {
	slog.Debug("sm.Decode", "SM(pre)", sm.String())

	// increment SSC
	sm.sscIncrement()

	var smRApdu *RApdu
	if smRApdu, err = ParseRApdu(rApduBytes); err != nil {
		return nil, fmt.Errorf("(sm.Decode) ParseRApdu error: %w", err)
	}

	// Simply return the SM rApdu if it doesn't contain any data, as SM (TLV)
	// decode will fail due to missing tags (e.g. 0x8E)
	if len(smRApdu.Data) < 1 {
		return smRApdu, nil
	}

	/*
	* Response APDU: [DO‘85’ or DO‘87’] [DO‘99’] DO‘8E’.
	 */

	tlv, err := tlv.Decode(smRApdu.Data)
	if err != nil {
		return nil, fmt.Errorf("[SM.Decode] error: %w", err)
	}

	tag85or87 := tlv.GetNode(0x85)
	if !tag85or87.IsValidNode() {
		tag85or87 = tlv.GetNode(0x87)
	}

	tag99 := tlv.GetNode(0x99)
	tag8E := tlv.GetNode(0x8E)

	if !tag8E.IsValidNode() {
		return nil, fmt.Errorf("(sm.Decode) tag 0x8E must be present")
	}

	// verify the MAC
	if err = sm.decodeVerifyMAC(tlv); err != nil {
		return nil, fmt.Errorf("(sm.Decode) verify MAC error: %w", err)
	}

	// set the status
	rApduStatus := binary.BigEndian.Uint16(tag99.GetValue())

	// sanity check that insecure/secure status values match
	if smRApdu.Status != rApduStatus {
		return nil, fmt.Errorf("(sm.Decode) rapdu status value mismatch (Insecure:%04x, Secure:%04x)", smRApdu.Status, rApduStatus)
	}

	// decrypt and unpad the data (if applicable)
	var rapduData []byte
	if tag85or87.IsValidNode() {
		rapduData, err = sm.decodeSmRApduData(tag85or87.GetValue())
		if err != nil {
			return nil, fmt.Errorf("(sm.Decode) error decoding rApduData: %w", err)
		}
	}

	rApdu = NewRApdu(rApduStatus, rapduData)

	slog.Debug("sm.Decode", "In", utils.BytesToHex(rApduBytes), "Out", rApdu.String())

	return rApdu, err
}
