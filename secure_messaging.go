package gmrtd

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"log"
	"log/slog"
	"math/big"

	"github.com/aead/cmac"
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
	alg       BlockCipherAlg
	KSenc     []byte
	KSmac     []byte
	SSC       []byte
	encCipher cipher.Block
	macCipher cipher.Block
}

func NewSecureMessaging(alg BlockCipherAlg, KSenc []byte, KSmac []byte) (sm *SecureMessaging, err error) {
	sm = new(SecureMessaging)

	// TODO - should we sanity check these? esp enc/mac length?
	sm.alg = alg
	sm.KSenc = KSenc
	sm.KSmac = KSmac

	if sm.encCipher, err = GetCipherForKey(sm.alg, KSenc); err != nil {
		return nil, err
	}

	if sm.macCipher, err = GetCipherForKey(sm.alg, KSmac); err != nil {
		return nil, err
	}

	// init SSC (based on block size)
	sm.SSC = make([]byte, sm.macCipher.BlockSize()) // TODO - why mac and not enc?

	slog.Debug("NewSecureMessaging", "SM", sm)

	return sm, nil
}

func (sm *SecureMessaging) SetSSC(ssc []byte) {
	if len(ssc) != len(sm.SSC) {
		log.Panicf("SSC length mismatch (exp:%d, act:%d)", len(sm.SSC), len(ssc))
	}
	copy(sm.SSC, ssc)
}

func (sm SecureMessaging) String() string {
	return fmt.Sprintf("{alg:%d, ksenc:%x, ksmac:%x, ssc:%x}", sm.alg, sm.KSenc, sm.KSmac, sm.SSC)
}

// increments the SSC and returns the post-increment value
func (sm *SecureMessaging) sscIncrement() {
	switch sm.alg {
	case TDES:
		binary.BigEndian.PutUint64(sm.SSC, binary.BigEndian.Uint64(sm.SSC)+1)
	case AES:
		var sscPre *big.Int = new(big.Int).SetBytes(sm.SSC)
		var sscPost *big.Int = new(big.Int)

		sscPost.Add(sscPre, big.NewInt(1))
		sscPost.FillBytes(sm.SSC)
	default:
		log.Panicf("Unsupported Alg (%d)", sm.alg)
	}
}

func (sm *SecureMessaging) cbcCrypt(data []byte, encrypt bool) []byte {
	// create 0'd IV
	iv := make([]byte, sm.encCipher.BlockSize())

	// special IV setup for AES
	if sm.alg == AES {
		// IV = K(KSenc,SSC)
		sm.encCipher.Encrypt(iv, sm.SSC)
	}

	out := CryptCBC(sm.encCipher, iv, data, encrypt)

	return out
}

// NB data must be padded to block boundary before calling
func (sm *SecureMessaging) generateMac(data []byte) (mac []byte, err error) {
	switch sm.alg {
	case TDES:
		if mac, err = ISO9797RetailMacDes(sm.KSmac, data); err != nil {
			return nil, err
		}
	case AES:
		var err error
		// CMAC-mode with MAC length of 8 bytes
		// AES [FIPS 197] SHALL be used in CMAC-mode [SP 800-38B] with a MAC length of 8 bytes.
		mac, err = cmac.Sum(data, sm.macCipher, 8)
		if err != nil {
			return nil, fmt.Errorf("unable to generate Auth-Token (CMAC): %s", err)
		}
	}

	slog.Debug("GenerateMac", "Data", data, "MAC", mac)

	return mac, nil
}

func (sm *SecureMessaging) cryptoPad(data []byte) []byte {
	// TODO - using the enc cipher.. but function also used for mac... should be ok.. but could be diff
	blockSize := sm.encCipher.BlockSize()

	return ISO9797Method2Pad(data, blockSize)
}

// NB fails if empty data passed in (as doesn't qualify the padding rules)
func (sm *SecureMessaging) cryptoUnpad(data []byte) []byte {
	return ISO9797Method2Unpad(data)
}

func (sm *SecureMessaging) Encode(cApdu *CApdu, maxLe uint64) (out *CApdu, err error) {
	// 9303p11 - page 63 (Message Structure of SM APDUs)

	if cApdu == nil {
		return nil, fmt.Errorf("CAPDU missing")
	}

	// increment SSC
	sm.sscIncrement()

	tlv := NewTlvNodes()

	// do85/do87
	if cApdu.HaveData() {
		var tag TlvTag
		if cApdu.ins%2 == 0 {
			tag = 0x87
		} else {
			tag = 0x85
		}

		value := []byte{0x01}
		value = append(value, sm.cbcCrypt(sm.cryptoPad(cApdu.data), true)...)

		tlv.AddNode(NewTlvSimpleNode(TlvTag(tag), value))
	}

	// do97
	if cApdu.HaveLe() {
		tlv.AddNode(NewTlvSimpleNode(TlvTag(0x97), cApdu.EncodeLe()))
	}

	// cmdHeader
	var cmdHeaderPadded []byte
	{
		cmdHeaderPadded = sm.cryptoPad(cApdu.EncodeHeader())
		// mask CLA
		cmdHeaderPadded[0] = CLA_MASK
	}

	// do8E
	{
		macData := make([]byte, 0)
		macData = append(macData, sm.SSC...)
		macData = append(macData, cmdHeaderPadded...)
		macData = append(macData, tlv.Encode()...)

		var mac []byte
		if mac, err = sm.generateMac(sm.cryptoPad(macData)); err != nil {
			return nil, err
		}

		tlv.AddNode(NewTlvSimpleNode(TlvTag(0x8E), mac))
	}

	out = NewCApdu(CLA_MASK, cApdu.ins, cApdu.p1, cApdu.p2, tlv.Encode(), int(maxLe))

	return out, nil
}

func (sm *SecureMessaging) Decode(rApduBytes []byte) (rApdu *RApdu, err error) {
	// increment SSC
	sm.sscIncrement()

	var smRApdu *RApdu
	if smRApdu, err = ParseRApdu(rApduBytes); err != nil {
		return nil, err
	}
	// TODO - check status code? error if not success
	// TODO - this should match the status-code in the payload... should check later

	{
		// Response APDU: [DO‘85’ or DO‘87’] [DO‘99’] DO‘8E’.

		tlv := TlvDecode(smRApdu.Data)

		tag85or87 := tlv.GetNode(0x85)
		if !tag85or87.IsValidNode() {
			tag85or87 = tlv.GetNode(0x87)
		}

		tag99 := tlv.GetNode(0x99)
		tag8E := tlv.GetNode(0x8E)

		if !tag8E.IsValidNode() {
			return nil, fmt.Errorf("Tag 0x8E must be present")
		}

		// verify the MAC
		{
			tmpData := make([]byte, 0)
			tmpData = append(tmpData, sm.SSC...)
			tmpData = append(tmpData, tlv.GetNode(0x85).Encode()...)
			tmpData = append(tmpData, tlv.GetNode(0x87).Encode()...)
			tmpData = append(tmpData, tlv.GetNode(0x99).Encode()...)

			var expMAC []byte
			if expMAC, err = sm.generateMac(sm.cryptoPad(tmpData)); err != nil {
				return nil, err
			}

			if !bytes.Equal(expMAC, tag8E.GetValue()) {
				return nil, fmt.Errorf("MAC mismatch (Exp: %x) (Act: %x)", expMAC, tag8E.GetValue())
			}
		}

		// decrypt and unpad the data (if applicable)
		var rapduData []byte
		if tag85or87.IsValidNode() {
			tmpBytes := tag85or87.GetValue()

			// field has a leading 'version' byte that needs to be removed (if field is present)

			// verify that 'verison' is 0x01 before removing
			if tmpBytes[0] != 0x01 {
				return nil, fmt.Errorf("Version not set to 0x01")
			}

			// remove the leading 'version' byte
			tmpBytes = tmpBytes[1:]

			rapduData = sm.cryptoUnpad(sm.cbcCrypt(tmpBytes, false))
		}

		rApdu = NewRApdu(binary.BigEndian.Uint16(tag99.GetValue()), rapduData)
	}

	return rApdu, err
}