package gmrtd

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"fmt"
	"log/slog"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/utils"
)

type BAC struct {
	randomBytesFn cryptoutils.RandomBytesFn
}

func NewBAC() *BAC {
	return &BAC{randomBytesFn: cryptoutils.RandomBytes}
}

func (bac *BAC) generateKseed(MRZi string) []byte {
	out := cryptoutils.CryptoHash(crypto.SHA1, []byte(MRZi))
	out = out[0:16]
	return out
}

// generates kEnc/kMac
func (bac *BAC) generateKeys(seed []byte) (kEnc []byte, kMac []byte) {
	kEnc = cryptoutils.KDF(seed, cryptoutils.KDF_COUNTER_KSENC, cryptoutils.TDES, 112)
	kMac = cryptoutils.KDF(seed, cryptoutils.KDF_COUNTER_KSMAC, cryptoutils.TDES, 112)
	return
}

func (bac *BAC) calculateMac(kMac []byte, data []byte) (mac []byte, err error) {
	mac, err = cryptoutils.ISO9797RetailMacDes(kMac, cryptoutils.ISO9797Method2Pad(data, cryptoutils.DES_BLOCK_SIZE_BYTES))
	return mac, err
}

// bac_cmd_data (40 bytes).. rnd-ifd(8), rnd_icc(8) kifd(16).. then encrypt (using kenc) and add 8 byte hmac
// rnd_ifd: 8 bytes
// rnd_icc: 8 bytes
// kifd: 16 bytes
func (bac *BAC) buildRequest(rndIfd []byte, rndIcc []byte, kIfd []byte, kEnc []byte, kMac []byte) (cmd []byte, err error) {
	utils.VerifyByteLength(rndIfd, 8)
	utils.VerifyByteLength(rndIcc, 8)
	utils.VerifyByteLength(kIfd, 16)

	s := make([]byte, 32)
	copy(s[0:8], rndIfd[0:8])
	copy(s[8:16], rndIcc[0:8])
	copy(s[16:32], kIfd[0:16])

	// eifd = encrypt with TDES key 'kenc'
	var cipher cipher.Block
	if cipher, err = cryptoutils.GetCipherForKey(cryptoutils.TDES, kEnc); err != nil {
		return nil, err
	}

	eIfd := cryptoutils.CryptCBC(cipher, make([]byte, cryptoutils.DES_BLOCK_SIZE_BYTES), s, true)

	// mifd = mac over eifd with kmac
	var mIfd []byte
	mIfd, err = bac.calculateMac(kMac, eIfd)
	if err != nil {
		return nil, err
	}

	// return eifd + mifd (40 bytes)
	cmd = make([]byte, 40)
	copy(cmd[0:32], eIfd[0:32])
	copy(cmd[32:40], mIfd[0:8])

	return cmd, nil
}

func (bac *BAC) processResponse(data []byte, kEnc []byte, kMac []byte, rndIfd []byte, rndIcc []byte) (kIcc []byte, err error) {
	rspCiphertext := make([]byte, 32)
	copy(rspCiphertext, data[0:32])

	rspMac := make([]byte, 8)
	copy(rspMac, data[32:40])

	// verify MAC
	{
		var expMac []byte

		expMac, err = bac.calculateMac(kMac, rspCiphertext)
		if err != nil {
			return nil, err
		}

		if !bytes.Equal(rspMac, expMac) {
			return nil, fmt.Errorf("MAC mismatch [Exp] %x [Act] %x", expMac, rspMac)
		}
	}

	// decrypt the cryptogram EIC
	var cipher cipher.Block
	cipher, err = cryptoutils.GetCipherForKey(cryptoutils.TDES, kEnc)
	if err != nil {
		return nil, err
	}

	rspPlaintext := cryptoutils.CryptCBC(cipher, make([]byte, 8), rspCiphertext, false)

	rspRndIcc := make([]byte, 8)
	copy(rspRndIcc, rspPlaintext[0:8])

	rspRndIfd := make([]byte, 8)
	copy(rspRndIfd, rspPlaintext[8:16])

	rspKIcc := make([]byte, 16)
	copy(rspKIcc, rspPlaintext[16:32])

	// verify RND.IFD matches original value
	if !bytes.Equal(rndIfd, rspRndIfd) {
		return nil, fmt.Errorf("RND.IFD mismatch (Exp: %x) (Act: %x)", rndIfd, rspRndIfd)
	}

	// verify RND.IC matches original value
	// NB spec doesn't explicitly mention this check, but they should match
	if !bytes.Equal(rndIcc, rspRndIcc) {
		return nil, fmt.Errorf("RND.IC mismatch (Exp: %x) (Act: %x)", rndIcc, rspRndIcc)
	}

	return rspKIcc, nil
}

func (bac *BAC) setupSecureMessaging(nfc *iso7816.NfcSession, kEnc []byte, kMac []byte, rndIc []byte, rndIfd []byte) (err error) {
	nfc.SM, err = iso7816.NewSecureMessaging(cryptoutils.TDES, kEnc, kMac)
	if err != nil {
		return err
	}

	// set the SSC
	// - BAC requires a custom SSC derived from IC/IFD Randoms
	ssc := make([]byte, 8)
	copy(ssc[0:4], rndIc[4:8])  // ls 4 bytes
	copy(ssc[4:8], rndIfd[4:8]) // ls 4 bytes
	nfc.SM.SetSSC(ssc)

	return nil
}

// TODO - return an indicator as to whether or not BAC was performed... same for PACE also
func (bac *BAC) doBAC(nfc *iso7816.NfcSession, password *Password) (err error) {
	slog.Debug("doBAC", "password-type", password.passwordType, "password", password.password)

	if password.passwordType != PASSWORD_TYPE_MRZi {
		// not supported, but not an error as caller shouldn't care
		slog.Debug("doBAC - SKIPPING as BAC is only supported for MRZi password types")
		return nil
	}

	kEnc, kMac := bac.generateKeys(bac.generateKseed(password.password))

	// request challenge (RND.IC) from the chip
	var rndIcc []byte
	rndIcc, err = nfc.GetChallenge(8)
	if err != nil {
		return err
	}

	// generate IFD randoms
	rndIfd := bac.randomBytesFn(8) // RND.IFD
	kIfd := bac.randomBytesFn(16)  // K.IFD

	// generate request message
	var bacReq []byte
	bacReq, err = bac.buildRequest(rndIfd, rndIcc, kIfd, kEnc, kMac)
	if err != nil {
		return err
	}

	// external authenticate
	var bacRsp []byte
	bacRsp, err = nfc.ExternalAuthenticate(bacReq, 40)
	// TODO - any error code for indicating BAC is not supported?.. so we don't have to return a misleading error
	if err != nil {
		return err
	}

	var kIc []byte
	kIc, err = bac.processResponse(bacRsp, kEnc, kMac, rndIfd, rndIcc)
	if err != nil {
		return err
	}

	kXor := utils.XorBytes(kIfd, kIc)

	// update kEnc/kMac with the derived key
	kEnc, kMac = bac.generateKeys(kXor)

	err = bac.setupSecureMessaging(nfc, kEnc, kMac, rndIcc, rndIfd)
	if err != nil {
		return err
	}

	return nil
}
