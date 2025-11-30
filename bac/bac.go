// Package bac implements the 'Basic Access Control' (BAC) authentication protocol.
package bac

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"log/slog"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/utils"
)

type BAC struct {
	randomBytesFn cryptoutils.RandomBytesFn
	nfcSession    **iso7816.NfcSession
	document      **document.Document
	password      *password.Password
}

func NewBAC(nfc *iso7816.NfcSession, doc *document.Document, pass *password.Password) *BAC {
	var bac BAC
	bac.randomBytesFn = cryptoutils.RandomBytes
	bac.nfcSession = &nfc
	bac.document = &doc
	bac.password = pass
	return &bac

}

func (bac *BAC) generateKseed(password *password.Password) []byte {
	tmpKey := password.Key()
	// NB only use first 16 bytes
	return tmpKey[0:16]
}

// generates kEnc/kMac
func (bac *BAC) generateKeys(seed []byte) (kEnc []byte, kMac []byte) {
	kEnc = cryptoutils.KDF(seed, cryptoutils.KDF_COUNTER_KSENC, cryptoutils.TDES, 112)
	kMac = cryptoutils.KDF(seed, cryptoutils.KDF_COUNTER_KSMAC, cryptoutils.TDES, 112)
	return
}

func (bac *BAC) calculateMac(kMac, data []byte) (mac []byte, err error) {
	mac, err = cryptoutils.ISO9797RetailMacDes(kMac, cryptoutils.ISO9797Method2Pad(data, cryptoutils.DES_BLOCK_SIZE_BYTES))
	return mac, err
}

// bac_cmd_data (40 bytes).. rnd-ifd(8), rnd_icc(8) kifd(16).. then encrypt (using kenc) and add 8 byte hmac
// rnd_ifd: 8 bytes
// rnd_icc: 8 bytes
// kifd: 16 bytes
func (bac *BAC) buildRequest(rndIfd, rndIcc, kIfd, kEnc, kMac []byte) (cmd []byte, err error) {
	// verify lengths of rndIfd(8) / rndIcc(8) / kIfd(16)
	if (len(rndIfd) != 8) || (len(rndIcc) != 8) || (len(kIfd) != 16) {
		return nil, fmt.Errorf("[buildRequest] incorrect length for rndIfd(%1d) and/or rndIcc(%1d) and/or kIfd(%1d)", len(rndIfd), len(rndIcc), len(kIfd))
	}

	s := make([]byte, 32)
	copy(s[0:8], rndIfd[0:8])
	copy(s[8:16], rndIcc[0:8])
	copy(s[16:32], kIfd[0:16])

	// eifd = encrypt with TDES key 'kenc'
	var cipher cipher.Block
	cipher, err = cryptoutils.CipherForKey(cryptoutils.TDES, kEnc)
	if err != nil {
		return nil, fmt.Errorf("[buildRequest] CipherForKey error: %w", err)
	}

	eIfd := cryptoutils.CryptCBC(cipher, make([]byte, cryptoutils.DES_BLOCK_SIZE_BYTES), s, true)

	// mifd = mac over eifd with kmac
	var mIfd []byte
	mIfd, err = bac.calculateMac(kMac, eIfd)
	if err != nil {
		return nil, fmt.Errorf("[buildRequest] calculateMac error: %w", err)
	}

	// return eifd + mifd (40 bytes)
	cmd = make([]byte, 40)
	copy(cmd[0:32], eIfd[0:32])
	copy(cmd[32:40], mIfd[0:8])

	return cmd, nil
}

func (bac *BAC) processResponse(data, kEnc, kMac, rndIfd, rndIcc []byte) (kIcc []byte, err error) {
	if len(data) != 40 {
		return nil, fmt.Errorf("[processResponse] data is not 40 bytes (len:%1d)", len(data))
	}

	rspCiphertext := make([]byte, 32)
	copy(rspCiphertext, data[0:32])

	rspMac := make([]byte, 8)
	copy(rspMac, data[32:40])

	// verify MAC
	{
		var expMac []byte

		expMac, err = bac.calculateMac(kMac, rspCiphertext)
		if err != nil {
			return nil, fmt.Errorf("[processResponse] calculateMac error: %w", err)
		}

		if !bytes.Equal(rspMac, expMac) {
			return nil, fmt.Errorf("[processResponse] MAC mismatch (Exp:%x, Act:%x)", expMac, rspMac)
		}
	}

	// decrypt the cryptogram EIC
	var cipher cipher.Block
	cipher, err = cryptoutils.CipherForKey(cryptoutils.TDES, kEnc)
	if err != nil {
		return nil, fmt.Errorf("[processResponse] CipherForKey error: %w", err)
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
		return nil, fmt.Errorf("[processResponse] RND.IFD mismatch (Exp: %x) (Act: %x)", rndIfd, rspRndIfd)
	}

	// verify RND.IC matches original value
	// NB spec doesn't explicitly mention this check, but they should match
	if !bytes.Equal(rndIcc, rspRndIcc) {
		return nil, fmt.Errorf("[processResponse] RND.IC mismatch (Exp: %x) (Act: %x)", rndIcc, rspRndIcc)
	}

	return rspKIcc, nil
}

func (bac *BAC) setupSecureMessaging(kEnc, kMac, rndIc, rndIfd []byte) (err error) {
	(*bac.nfcSession).SM, err = iso7816.NewSecureMessaging(cryptoutils.TDES, kEnc, kMac)
	if err != nil {
		return fmt.Errorf("[setupSecureMessaging] NewSecureMessaging error: %w", err)
	}

	// set the SSC
	// - BAC requires a custom SSC derived from IC/IFD Randoms
	ssc := make([]byte, 8)
	copy(ssc[0:4], rndIc[4:8])  // ls 4 bytes
	copy(ssc[4:8], rndIfd[4:8]) // ls 4 bytes
	(*bac.nfcSession).SM.SetSSC(ssc)

	return nil
}

func (bac *BAC) DoBAC() (result *document.BacResult, err error) {
	slog.Debug("DoBAC", "password-type", bac.password.PasswordType, "password", bac.password.Password)

	if bac.password.PasswordType != password.PASSWORD_TYPE_MRZi {
		// not supported, but not an error as caller shouldn't care
		slog.Debug("DoBAC - SKIPPING as BAC is only supported for MRZi password types", "passwordType", bac.password.PasswordType)
		return nil, nil
	}

	// setup the result (but mark as !success)
	result = &document.BacResult{Success: false}

	kEnc, kMac := bac.generateKeys(bac.generateKseed(bac.password))

	// request challenge (RND.IC) from the chip
	var rndIcc []byte
	rndIcc, err = (*bac.nfcSession).GetChallenge(8)
	if err != nil {
		return result, fmt.Errorf("[DoBAC] GetChallenge error: %w", err)
	}

	// generate IFD randoms
	rndIfd := bac.randomBytesFn(8) // RND.IFD
	kIfd := bac.randomBytesFn(16)  // K.IFD

	// generate request message
	var bacReq []byte
	bacReq, err = bac.buildRequest(rndIfd, rndIcc, kIfd, kEnc, kMac)
	if err != nil {
		return result, fmt.Errorf("[DoBAC] buildRequest error: %w", err)
	}

	// external authenticate
	var bacRsp []byte
	bacRsp, err = (*bac.nfcSession).ExternalAuthenticate(bacReq, 40)
	if err != nil {
		return result, fmt.Errorf("[DoBAC] ExternalAuthenticate error: %w", err)
	}

	var kIc []byte
	kIc, err = bac.processResponse(bacRsp, kEnc, kMac, rndIfd, rndIcc)
	if err != nil {
		return result, fmt.Errorf("[DoBAC] processResponse error: %w", err)
	}

	kXor := utils.XorBytes(kIfd, kIc)

	// update kEnc/kMac with the derived key
	kEnc, kMac = bac.generateKeys(kXor)

	err = bac.setupSecureMessaging(kEnc, kMac, rndIcc, rndIfd)
	if err != nil {
		return result, fmt.Errorf("[DoBAC] setupSecureMessaging error: %w", err)
	}

	// update result to indicate success
	result.Success = true

	return result, nil
}
