package iso7816

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
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

// CLA_MASK is the CLA byte of a secure messaging C-APDU, indicating that the command header
// is included in the MAC (ICAO Doc 9303 Part 11).
const CLA_MASK byte = 0x0C

// SecureMessenger protects C-APDUs and unprotects R-APDUs for an NfcSession. SecureMessaging
// is the implementation.
type SecureMessenger interface {
	SSC() []byte
	SetSSC([]byte) error
	KsEnc() []byte
	String() string
	Encode(*CApdu) (*CApdu, error)
	Decode([]byte) (*RApdu, error)
}

// SecureMessaging implements ICAO Doc 9303 Part 11 secure messaging with 3DES (retail MAC)
// or AES (CMAC) session keys and a send sequence counter (SSC). It is not safe for concurrent
// use.
type SecureMessaging struct {
	alg       cryptoutils.BlockCipherAlg
	ksEnc     []byte
	ksMac     []byte
	ssc       []byte
	encCipher cipher.Block
	macCipher cipher.Block
}

// verify that SecureMessaging conforms to SecureMessenger
var _ SecureMessenger = (*SecureMessaging)(nil)

// Equal reports whether sm1 and sm2 have the same algorithm, session keys and SSC.
func (sm1 SecureMessaging) Equal(sm2 SecureMessaging) bool {
	if (sm1.alg == sm2.alg) &&
		bytes.Equal(sm1.ksEnc, sm2.ksEnc) &&
		bytes.Equal(sm1.ksMac, sm2.ksMac) &&
		bytes.Equal(sm1.ssc, sm2.ssc) {
		return true
	}

	return false
}

// KsEnc returns a copy of the encryption session key.
func (sm SecureMessaging) KsEnc() []byte {
	return bytes.Clone(sm.ksEnc)
}

// SSC returns a copy of the current send sequence counter.
func (sm SecureMessaging) SSC() []byte {
	return bytes.Clone(sm.ssc)
}

// NewSecureMessaging returns secure messaging for alg with the encryption key ksEnc and MAC
// key ksMac, and an all-zero SSC the length of the cipher's block. It returns an error if
// either key is invalid for alg.
func NewSecureMessaging(alg cryptoutils.BlockCipherAlg, ksEnc []byte, ksMac []byte) (sm *SecureMessaging, err error) {
	sm = new(SecureMessaging)

	sm.alg = alg
	sm.ksEnc = ksEnc
	sm.ksMac = ksMac

	if sm.encCipher, err = cryptoutils.CipherForKey(sm.alg, ksEnc); err != nil {
		return nil, fmt.Errorf("(NewSecureMessaging) CipherForKey:ksEnc: %w", err)
	}

	if sm.macCipher, err = cryptoutils.CipherForKey(sm.alg, ksMac); err != nil {
		return nil, fmt.Errorf("(NewSecureMessaging) CipherForKey:ksMac: %w", err)
	}

	// init SSC (based on block size)
	// NB we use the encryption block-size as crypt/mac are always the same algorithm
	sm.ssc = make([]byte, sm.encCipher.BlockSize())

	slog.Debug("NewSecureMessaging", "SM", sm.String())

	return sm, nil
}

// SetSSC sets the send sequence counter, e.g. to the value derived during BAC. It returns an
// error if ssc is not the cipher's block size.
func (sm *SecureMessaging) SetSSC(ssc []byte) error {
	if len(ssc) != len(sm.ssc) {
		return fmt.Errorf("[SetSSC] length mismatch (exp:%d, act:%d)", len(sm.ssc), len(ssc))
	}
	copy(sm.ssc, ssc)
	slog.Debug("SetSSC", "SSC", utils.BytesToHex(sm.ssc))

	return nil
}

// String omits the session keys: SM state is logged at debug level, and logs may be shared.
func (sm SecureMessaging) String() string {
	return fmt.Sprintf("(alg:%d, ssc:%x)", sm.alg, sm.ssc)
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

// decrements the SSC (mirror of sscIncrement) - used to undo a prior increment
// when we believe the corresponding capdu was not processed by the chip.
func (sm *SecureMessaging) sscDecrement() {
	var sscPre *big.Int = new(big.Int).SetBytes(sm.ssc)

	if sscPre.Sign() == 0 {
		// handle underflow condition - wrap to max value, mirroring the
		// overflow wrap in sscIncrement
		for i := range sm.ssc {
			sm.ssc[i] = 0xFF
		}
		return
	}

	var sscPost *big.Int = new(big.Int).Sub(sscPre, big.NewInt(1))
	sscPost.FillBytes(sm.ssc)
}

func (sm *SecureMessaging) cbcCrypt(data []byte, encrypt bool) ([]byte, error) {
	// create 0'd IV
	iv := make([]byte, sm.encCipher.BlockSize())

	// special IV setup for AES
	if sm.alg == cryptoutils.AES {
		// IV = K(KSenc,SSC)
		// Note: suppress secure mode and padding scheme warning in sonar
		//		 - this is required for setting up the IV for AES
		sm.encCipher.Encrypt(iv, sm.ssc) // NOSONAR
	}

	out, err := cryptoutils.CryptCBC(sm.encCipher, iv, data, encrypt)
	if err != nil {
		return nil, fmt.Errorf("[cbcCrypt] CryptCBC error: %w", err)
	}

	return out, nil
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
			return nil, fmt.Errorf("unable to generate Auth-Token (CMAC): %w", err)
		}
	}

	return mac, nil
}

func (sm *SecureMessaging) cryptoPad(data []byte) []byte {
	// NB we use the encryption block-size as crypt/mac are always the same algorithm
	return cryptoutils.ISO9797Method2Pad(data, sm.encCipher.BlockSize())
}

// NB fails if empty data passed in (as doesn't qualify the padding rules)
func (sm *SecureMessaging) cryptoUnpad(data []byte) ([]byte, error) {
	data, err := cryptoutils.ISO9797Method2Unpad(data)
	if err != nil {
		return nil, fmt.Errorf("[cryptoUnpad] ISO9797Method2Unpad error: %w", err)
	}

	return data, nil
}

// builds tag 85/87 (depending on Ins)
// adds the tag (if any) to 'nodes'
func (sm *SecureMessaging) buildTag85or87(cApdu *CApdu, nodes *tlv.TlvNodes) error {
	if cApdu.HaveData() {
		value, err := sm.cbcCrypt(sm.cryptoPad(cApdu.data), true)
		if err != nil {
			return fmt.Errorf("[buildTag85or87] cbcCrypt error: %w", err)
		}
		// ICAO 9303 supplement R2-p1_v2_sIV_0033: only DO87 carries a padding indicator.
		tag := tlv.TlvTag(0x85)
		if cApdu.ins%2 == 0 {
			tag = 0x87
			value = append([]byte{0x01}, value...)
		}
		nodes.AddNode(tlv.NewTlvSimpleNode(tag, value))
	}

	return nil
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

// Encode increments the SSC and returns cApdu protected with secure messaging: data
// encrypted in DO'87' (even INS) or DO'85' (odd INS), Le in DO'97' and the MAC in DO'8E',
// with CLA 0x0C and Le set to the maximum. It returns an error if cApdu is nil.
func (sm *SecureMessaging) Encode(cApdu *CApdu) (out *CApdu, err error) {
	// 9303p11 - page 63 (Message Structure of SM APDUs)

	slog.Debug("Encode", "SM(pre)", sm.String())

	if cApdu == nil {
		return nil, fmt.Errorf("CAPDU missing")
	}

	// increment SSC
	sm.sscIncrement()

	var nodes *tlv.TlvNodes = &tlv.TlvNodes{}

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
	out = append(out, smRApduTlv.NodeByTag(0x85).Encode()...)
	out = append(out, smRApduTlv.NodeByTag(0x87).Encode()...)
	out = append(out, smRApduTlv.NodeByTag(0x99).Encode()...)
	return out
}

func (sm *SecureMessaging) decodeVerifyMAC(tlv *tlv.TlvNodes) error {
	macData := generateMacDataForSmRApduTlv(tlv, sm.ssc)
	actMAC := tlv.NodeByTag(0x8E).Value()

	expMAC, err := sm.generateMac(sm.cryptoPad(macData))
	if err != nil {
		return fmt.Errorf("(sm.decodeVerifyMAC) generateMac error: %w", err)
	}

	if !hmac.Equal(expMAC, actMAC) {
		return fmt.Errorf("(sm.decodeVerifyMAC) MAC mismatch")
	}

	return nil
}

func (sm *SecureMessaging) decodeSmRApduData(tag tlv.TlvTag, encodedData []byte) (out []byte, err error) {
	if len(encodedData) == 0 {
		return nil, fmt.Errorf("[sm.decodeSmRApduData] encodeData must be >= 1 bytes")
	}
	if tag == 0x87 {
		if encodedData[0] != 0x01 {
			return nil, fmt.Errorf("[sm.decodeSmRApduData] version not set to 0x01")
		}
		encodedData = encodedData[1:]
	}

	tmpDecryptedValue, err := sm.cbcCrypt(encodedData, false)
	if err != nil {
		return nil, fmt.Errorf("[sm.decodeSmRApduData] cbcCrypt error: %w", err)
	}

	out, err = sm.cryptoUnpad(tmpDecryptedValue)
	if err != nil {
		return nil, fmt.Errorf("[sm.decodeSmRApduData] cryptoUnpad error: %w", err)
	}

	return out, nil
}

// Decode verifies and unprotects a secure messaging R-APDU, returning the protected status
// word from DO'99' and the decrypted data, if any. It returns an error if the MAC does not
// match or the protected and plain status words differ. A response with no data (e.g. a
// plain error status) is rejected and the SSC increment made by Encode is undone.
func (sm *SecureMessaging) Decode(rApduBytes []byte) (rApdu *RApdu, err error) {
	slog.Debug("sm.Decode", "SM(pre)", sm.String())

	var smRApdu *RApdu
	if smRApdu, err = ParseRApdu(rApduBytes); err != nil {
		return nil, fmt.Errorf("(sm.Decode) ParseRApdu error: %w", err)
	}

	// Return error if the rApdu doesn't contain any data, as this is mandatory for an SM response
	if len(smRApdu.Data) < 1 {
		// naked response - the chip almost certainly never accepted our SM-wrapped
		// capdu, so undo the increment Encode() made for it, keeping this SM
		// instance's counter aligned with the chip's for any future command.
		slog.Warn("sm.Decode: naked response received, decrementing SSC", "SSC", utils.BytesToHex(sm.ssc), "Status", fmt.Sprintf("%4x", smRApdu.Status))
		sm.sscDecrement()

		return nil, fmt.Errorf("[SM.Decode] Unable to decode SM-RApdu due to missing data. Advertised(insecure) status:%4x", smRApdu.Status)
	}

	// increment SSC
	// - we only increment if it looks like we got an SM-wrapped rapdu (i.e. we got some data)
	sm.sscIncrement()

	/*
	* Response APDU: [DO‘85’ or DO‘87’] [DO‘99’] DO‘8E’.
	 */

	tlv, err := tlv.Decode(smRApdu.Data)
	if err != nil {
		return nil, fmt.Errorf("[SM.Decode] error: %w", err)
	}

	tag85or87 := tlv.NodeByTag(0x85)
	if !tag85or87.IsValidNode() {
		tag85or87 = tlv.NodeByTag(0x87)
	}

	tag99 := tlv.NodeByTag(0x99)
	tag8E := tlv.NodeByTag(0x8E)

	if !tag8E.IsValidNode() {
		return nil, fmt.Errorf("(sm.Decode) tag 0x8E must be present")
	}

	// verify the MAC
	if err = sm.decodeVerifyMAC(tlv); err != nil {
		return nil, fmt.Errorf("(sm.Decode) verify MAC error: %w", err)
	}

	// verify status is 2 bytes
	if len(tag99.Value()) != 2 {
		return nil, fmt.Errorf("[sm.Decode] Protected status (tag 99) must be 2 bytes (act-len:%1d)", len(tag99.Value()))
	}

	// set the status
	rApduStatus := binary.BigEndian.Uint16(tag99.Value())

	// sanity check that insecure/secure status values match
	if smRApdu.Status != rApduStatus {
		return nil, fmt.Errorf("(sm.Decode) rapdu status value mismatch (Insecure:%04x, Secure:%04x)", smRApdu.Status, rApduStatus)
	}

	// decrypt and unpad the data (if applicable)
	var rapduData []byte
	if tag85or87.IsValidNode() {
		rapduData, err = sm.decodeSmRApduData(tag85or87.Tag(), tag85or87.Value())
		if err != nil {
			return nil, fmt.Errorf("(sm.Decode) error decoding rApduData: %w", err)
		}
	}

	rApdu = NewRApdu(rApduStatus, rapduData)

	// Not the decrypted data: it holds chip file contents, i.e. the holder's personal data.
	slog.Debug("sm.Decode", "Status", fmt.Sprintf("%04x", rApdu.Status), "DataLen", len(rApdu.Data))

	return rApdu, err
}
