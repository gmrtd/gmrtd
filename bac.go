package gmrtd

import (
	"bytes"
	"log"
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
func bacCmdData(rndIfd []byte, rndIcc []byte, kIfd []byte, kEnc []byte, kMac []byte) []byte {
	VerifyByteLength(rndIfd, 8)
	VerifyByteLength(rndIcc, 8)
	VerifyByteLength(kIfd, 16)

	s := make([]byte, 32)
	copy(s[0:8], rndIfd[0:8])
	copy(s[8:16], rndIcc[0:8])
	copy(s[16:32], kIfd[0:16])

	// eifd = encrypt with TDES key 'kenc'
	eIfd := CryptCBC(GetCipherForKey(TDES, kEnc), make([]byte, DES_BLOCK_SIZE_BYTES), s, true)

	// mifd = mac over eifd with kmac
	mIfd := ISO9797RetailMacDes(kMac, ISO9797Method2Pad(eIfd, DES_BLOCK_SIZE_BYTES))

	// return eifd + mifd (40 bytes)
	out := make([]byte, 40)
	copy(out[0:32], eIfd[0:32])
	copy(out[32:40], mIfd[0:8])

	return out
}

func (bac *BAC) DoBAC(nfc *NfcSession, password *Password) {
	if password.passwordType != PASSWORD_TYPE_MRZi {
		log.Panicf("BAC only supports MRZi passwords (PasswordType:%d)", password.passwordType)
	}

	kSEED := generateKseed(password.password)

	kENC := KDF(kSEED, KDF_COUNTER_KSENC, TDES, 112)

	kMAC := KDF(kSEED, KDF_COUNTER_KSMAC, TDES, 112)

	// request challenge (RND.IC) from the chip
	rxRNDIC := nfc.GetChallenge(8)
	VerifyByteLength(rxRNDIC, 8)

	// RND.IFD
	txRNDIFD := bac.randomBytesFn(8)

	// K.IFD
	txKIFD := bac.randomBytesFn(16)

	// bac_cmd_data (40 bytes).. rnd-ifd(8), rnd_icc(8) kifd(16).. then encrypt (using kenc) and add 8 byte hmac
	bacCmd := bacCmdData(txRNDIFD, rxRNDIC, txKIFD, kENC, kMAC)

	VerifyByteLength(bacCmd, 40)

	// TODO - any error code for indicating BAC is not supported?
	// external authenticate
	extAuthBytes := nfc.ExternalAuthenticate(bacCmd, 40)

	rxEIC := make([]byte, 32)
	copy(rxEIC, extAuthBytes[0:32])

	rxMIC := make([]byte, 8)
	copy(rxMIC, extAuthBytes[32:40])

	// verify MAC
	{
		expMAC := ISO9797RetailMacDes(kMAC, ISO9797Method2Pad(rxEIC, DES_BLOCK_SIZE_BYTES))
		if !bytes.Equal(rxMIC, expMAC) {
			log.Panicf("MAC mismatch\n[Act] %x\n[Exp] %x", rxMIC, expMAC)
		}
	}

	// decrypt the cryptogram EIC
	rxEICplaintext := CryptCBC(GetCipherForKey(TDES, kENC), make([]byte, 8), rxEIC, false)

	rxRNDIC2 := make([]byte, 8)
	copy(rxRNDIC2, rxEICplaintext[0:8])

	rxRNDIFD := make([]byte, 8)
	copy(rxRNDIFD, rxEICplaintext[8:16])

	rxKIC := make([]byte, 16)
	copy(rxKIC, rxEICplaintext[16:32])

	// verify RND.IFD matches original value
	if !bytes.Equal(rxRNDIFD, txRNDIFD) {
		log.Panicf("RND.IFD mismatch (Exp: %x) (Act: %x)", txRNDIFD, rxRNDIFD)
	}

	// verify RND.IC matches original value
	// NB spec doesn't explicitly mention this check, but they should match
	if !bytes.Equal(rxRNDIC, rxRNDIC2) {
		log.Panicf("RND.IC mismatch (Exp: %x) (Act: %x)", rxRNDIC, rxRNDIC2)
	}

	kXor := XorBytes(txKIFD, rxKIC)

	KSenc := KDF(kXor, KDF_COUNTER_KSENC, TDES, 112)
	KSmac := KDF(kXor, KDF_COUNTER_KSMAC, TDES, 112)

	nfc.sm = NewSecureMessaging(TDES, KSenc, KSmac)

	// set the SSC (special handling for BAC)
	{
		ssc := make([]byte, 8)
		copy(ssc[0:4], rxRNDIC[4:8])  // ls 4 bytes
		copy(ssc[4:8], txRNDIFD[4:8]) // ls 4 bytes

		nfc.sm.SetSSC(ssc)
	}
}
