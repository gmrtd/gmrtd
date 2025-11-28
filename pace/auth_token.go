package pace

import (
	"crypto/cipher"
	"crypto/elliptic"
	"fmt"
	"log/slog"

	"github.com/aead/cmac"
	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

/*
* 9303p11
*
* 4.4.3.4 Authentication Token
*
* 	The authentication token SHALL be computed over a public key data object (cf. Section 9.4) containing the object
* 	identifier as indicated in MSE:Set AT (cf. Section 4.4.4.1), and the received ephemeral public key (i.e. excluding the
* 	domain parameters, cf. Section 9.4.5) using an authentication code and the key KSMAC derived from the key agreement.
*
* Note. — Padding is performed internally by the message authentication code, i.e. no application specific
* 		  padding is performed.
*
* 3DES
*
* 	3DES [FIPS 46-3] SHALL be used in Retail-mode according to [ISO/IEC 9797-1] MAC algorithm 3 / padding method 2
* 	with block cipher DES and IV=0.
*
* AES
*
* 	AES [FIPS 197] SHALL be used in CMAC-mode [SP 800-38B] with a MAC length of 8 bytes.
 */

func (paceConfig *PaceConfig) computeAuthToken(key []byte, data []byte) ([]byte, error) {
	slog.Debug("computeAuthToken", "key", utils.BytesToHex(key), "data", utils.BytesToHex(data))

	switch paceConfig.authToken {
	case CBC:
		// CBC-mode with MAC length of 8 bytes
		// 3DES [FIPS 46-3] SHALL be used in Retail-mode according to [ISO/IEC 9797-1] MAC algorithm 3 / padding method 2 with block cipher DES and IV=0.

		if paceConfig.cipher != cryptoutils.TDES {
			return nil, fmt.Errorf("[computeAuthToken] CBC Authentication Token is only supported for 3DES (ActCipherAlg:%d)", int(paceConfig.cipher))
		}

		var err error
		var authToken []byte

		authToken, err = cryptoutils.ISO9797RetailMacDes(key, cryptoutils.ISO9797Method2Pad(data, cryptoutils.DES_BLOCK_SIZE_BYTES))
		if err != nil {
			return nil, fmt.Errorf("[computeAuthToken] ISO9797RetailMacDes error: %w", err)
		}

		slog.Debug("computeAuthToken", "authToken(CBC)", utils.BytesToHex(authToken))

		return authToken, nil
	case CMAC:
		// CMAC-mode with MAC length of 8 bytes
		// AES [FIPS 197] SHALL be used in CMAC-mode [SP 800-38B] with a MAC length of 8 bytes.

		if paceConfig.cipher != cryptoutils.AES {
			return nil, fmt.Errorf("[computeAuthToken] CMAC Authentication Token is only supported for AES (ActCipherAlg:%d)", int(paceConfig.cipher))
		}

		var err error
		var cipher cipher.Block

		cipher, err = cryptoutils.CipherForKey(paceConfig.cipher, key)
		if err != nil {
			return nil, fmt.Errorf("[computeAuthToken] CipherForKey error: %w", err)
		}

		authToken, err := cmac.Sum(data, cipher, 8)
		if err != nil {
			return nil, fmt.Errorf("[computeAuthToken] cmac.Sum error: %w", err)
		}

		slog.Debug("computeAuthToken", "authToken(CMAC)", utils.BytesToHex(authToken))

		return authToken, nil
	}

	return nil, fmt.Errorf("[computeAuthToken] Unsupported auth-token alg (%x)", paceConfig.authToken)
}

func (paceConfig *PaceConfig) computeAuthTokens(ksMac []byte, ec elliptic.Curve, termPub, chipPub *cryptoutils.EcPoint) (tIfd []byte, tIc []byte, err error) {
	oidBytes := oid.OidBytes(paceConfig.oid)

	tIfdData := encodePubicKeyTemplate7F49(oidBytes, cryptoutils.EncodeX962EcPoint(ec, chipPub))
	tIcData := encodePubicKeyTemplate7F49(oidBytes, cryptoutils.EncodeX962EcPoint(ec, termPub))

	// TODO - should we verify that tIdfData != tIcData?

	// generate auth tokens
	tIfd, err = paceConfig.computeAuthToken(ksMac, tIfdData)
	if err != nil {
		return nil, nil, fmt.Errorf("[computeAuthTokens] computeAuthToken(tIdf) error: %w", err)
	}

	tIc, err = paceConfig.computeAuthToken(ksMac, tIcData)
	if err != nil {
		return nil, nil, fmt.Errorf("[computeAuthTokens] computeAuthToken(tIc) error: %w", err)
	}

	return tIfd, tIc, nil
}
