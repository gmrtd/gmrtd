package gmrtd

import (
	"bytes"
	"crypto/cipher"
	"fmt"
)

type BAC struct {
	randomBytesFn RandomBytesFn
}

func NewBAC() *BAC {
	return &BAC{randomBytesFn: RandomBytes}
}

func generateKseed(MRZi string) []byte {
	out := CryptoHash(SHA1, []byte(MRZi))
	out = out[0:16]
	return out
}

// rnd_ifd: 8 bytes
// rnd_icc: 8 bytes
// kifd: 16 bytes
func bacCmdData(rndIfd []byte, rndIcc []byte, kIfd []byte, kEnc []byte, kMac []byte) (cmd []byte, err error) {
	VerifyByteLength(rndIfd, 8)
	VerifyByteLength(rndIcc, 8)
	VerifyByteLength(kIfd, 16)

	s := make([]byte, 32)
	copy(s[0:8], rndIfd[0:8])
	copy(s[8:16], rndIcc[0:8])
	copy(s[16:32], kIfd[0:16])

	// eifd = encrypt with TDES key 'kenc'
	var cipher cipher.Block
	if cipher, err = GetCipherForKey(TDES, kEnc); err != nil {
		return nil, err
	}

	eIfd := CryptCBC(cipher, make([]byte, DES_BLOCK_SIZE_BYTES), s, true)

	// mifd = mac over eifd with kmac
	var mIfd []byte
	if mIfd, err = ISO9797RetailMacDes(kMac, ISO9797Method2Pad(eIfd, DES_BLOCK_SIZE_BYTES)); err != nil {
		return nil, err
	}

	// return eifd + mifd (40 bytes)
	cmd = make([]byte, 40)
	copy(cmd[0:32], eIfd[0:32])
	copy(cmd[32:40], mIfd[0:8])

	return cmd, nil
}

// TODO - return an indicator as to whether or not BAC was performed... same for PACE also
func (bac *BAC) DoBAC(nfc *NfcSession, password *Password) (err error) {
	if password.passwordType != PASSWORD_TYPE_MRZi {
		// not supported, but not an error as caller shouldn't care
		return nil
	}

	kSeed := generateKseed(password.password)

	kEnc := KDF(kSeed, KDF_COUNTER_KSENC, TDES, 112)

	kMac := KDF(kSeed, KDF_COUNTER_KSMAC, TDES, 112)

	var rxRndIC []byte
	// request challenge (RND.IC) from the chip
	if rxRndIC, err = nfc.GetChallenge(8); err != nil {
		return err
	}

	VerifyByteLength(rxRndIC, 8)

	// RND.IFD
	txRndIfd := bac.randomBytesFn(8)

	// K.IFD
	txKIFD := bac.randomBytesFn(16)

	// bac_cmd_data (40 bytes).. rnd-ifd(8), rnd_icc(8) kifd(16).. then encrypt (using kenc) and add 8 byte hmac
	var bacCmd []byte
	if bacCmd, err = bacCmdData(txRndIfd, rxRndIC, txKIFD, kEnc, kMac); err != nil {
		return err
	}

	VerifyByteLength(bacCmd, 40)

	// TODO - any error code for indicating BAC is not supported?
	// external authenticate
	var extAuthBytes []byte
	if extAuthBytes, err = nfc.ExternalAuthenticate(bacCmd, 40); err != nil {
		return err
	}

	rxEIC := make([]byte, 32)
	copy(rxEIC, extAuthBytes[0:32])

	rxMIC := make([]byte, 8)
	copy(rxMIC, extAuthBytes[32:40])

	// verify MAC
	{
		var expMac []byte

		if expMac, err = ISO9797RetailMacDes(kMac, ISO9797Method2Pad(rxEIC, DES_BLOCK_SIZE_BYTES)); err != nil {
			return err
		}

		if !bytes.Equal(rxMIC, expMac) {
			return fmt.Errorf("MAC mismatch\n[Act] %x\n[Exp] %x", rxMIC, expMac)
		}
	}

	// decrypt the cryptogram EIC
	var cipher cipher.Block
	if cipher, err = GetCipherForKey(TDES, kEnc); err != nil {
		return err
	}
	rxEICplaintext := CryptCBC(cipher, make([]byte, 8), rxEIC, false)

	rxRndIc2 := make([]byte, 8)
	copy(rxRndIc2, rxEICplaintext[0:8])

	rxRndIfd := make([]byte, 8)
	copy(rxRndIfd, rxEICplaintext[8:16])

	rxKIC := make([]byte, 16)
	copy(rxKIC, rxEICplaintext[16:32])

	// verify RND.IFD matches original value
	if !bytes.Equal(rxRndIfd, txRndIfd) {
		return fmt.Errorf("RND.IFD mismatch (Exp: %x) (Act: %x)", txRndIfd, rxRndIfd)
	}

	// verify RND.IC matches original value
	// NB spec doesn't explicitly mention this check, but they should match
	if !bytes.Equal(rxRndIC, rxRndIc2) {
		return fmt.Errorf("RND.IC mismatch (Exp: %x) (Act: %x)", rxRndIC, rxRndIc2)
	}

	kXor := XorBytes(txKIFD, rxKIC)

	KSenc := KDF(kXor, KDF_COUNTER_KSENC, TDES, 112)
	KSmac := KDF(kXor, KDF_COUNTER_KSMAC, TDES, 112)

	if nfc.sm, err = NewSecureMessaging(TDES, KSenc, KSmac); err != nil {
		return err
	}

	// set the SSC (special handling for BAC)
	{
		ssc := make([]byte, 8)
		copy(ssc[0:4], rxRndIC[4:8])  // ls 4 bytes
		copy(ssc[4:8], txRndIfd[4:8]) // ls 4 bytes

		nfc.sm.SetSSC(ssc)
	}

	return nil
}
