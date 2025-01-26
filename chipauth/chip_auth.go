// Package chipauth implements the 'Chip Authentication' mechanism for verifying the authenticity of the Contactless IC.
package chipauth

import (
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"log/slog"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

type ChipAuth struct {
	keyGeneratorEc cryptoutils.KeyGeneratorEcFn
}

func NewChipAuth() *ChipAuth {
	var chipAuth ChipAuth
	chipAuth.keyGeneratorEc = cryptoutils.KeyGeneratorEc
	return &chipAuth
}

func (chipAuth *ChipAuth) DoChipAuth(nfc *iso7816.NfcSession, doc *document.Document) (err error) {
	// skip if we have already performed chip authentication
	if doc.ChipAuthStatus != document.CHIP_AUTH_STATUS_NONE {
		return nil
	}

	// skip if DG14 is missing
	if doc.Mf.Lds1.Dg14 == nil {
		slog.Debug("doChipAuth - skipping CA as DG14 is not present")
		return nil
	}

	if nfc.SM != nil {
		slog.Debug("doChipAuth", "SM(pre)", nfc.SM.String())
	}

	var caInfo *document.ChipAuthenticationInfo
	var caAlgInfo *CaAlgorithmInfo

	caInfo, caAlgInfo, err = selectCAInfo(doc)
	if err != nil {
		return err
	} else if caInfo == nil || caAlgInfo == nil {
		// try to infer from any available CA key
		caInfo, caAlgInfo, err = inferCAInfoFromKey(doc)
		if err != nil {
			return err
		}
	}

	if caInfo == nil || caAlgInfo == nil {
		// cannot proceed with CA
		slog.Info("DoChipAuth - skipping")
		return nil
	}

	var caPubKeyInfo *document.ChipAuthenticationPublicKeyInfo

	caPubKeyInfo, err = selectCAPubKeyInfo(caInfo, caAlgInfo, doc)
	if err != nil {
		return err
	}

	// process based on the type of key (DH/ECDH)
	if caPubKeyInfo.Protocol.Equal(oid.OidPkDh) {
		// DH
		return fmt.Errorf("chipAuth: DH not currently supported (Raw:%x)", caPubKeyInfo.Raw)
	} else if caPubKeyInfo.Protocol.Equal(oid.OidPkEcdh) {
		// ECDH
		err = chipAuth.doCaEcdh(nfc, caInfo, caAlgInfo, caPubKeyInfo)
		if err != nil {
			return err
		}
		// record chip-auth status
		doc.ChipAuthStatus = document.CHIP_AUTH_STATUS_CA
	} else {
		return fmt.Errorf("chipAuth: unsupported public key type (OID:%s)", caPubKeyInfo.Protocol.String())
	}

	if nfc.SM != nil {
		slog.Debug("doChipAuth", "SM(post)", nfc.SM.String())
	}

	return nil
}

// selects the 'preferred' CA entry (if any are present)
// returns: nil (caAuthInfo/caAlgInfo) if none found, otherwise preferred CA entry
func selectCAInfo(doc *document.Document) (caInfo *document.ChipAuthenticationInfo, caAlgInfo *CaAlgorithmInfo, err error) {
	slog.Debug("selectCAInfo")

	var bestCaInfo *document.ChipAuthenticationInfo
	var bestCaAlgInfo *CaAlgorithmInfo

	for i := range doc.Mf.Lds1.Dg14.SecInfos.ChipAuthInfos {
		var curCaInfo *document.ChipAuthenticationInfo
		var curCaAlgInfo *CaAlgorithmInfo

		curCaInfo = &(doc.Mf.Lds1.Dg14.SecInfos.ChipAuthInfos[i])

		curCaAlgInfo, err = getAlgInfo(curCaInfo.Protocol)
		if err != nil {
			return nil, nil, err
		}

		// first valid entry, so record as best
		// *OR* current has higher weight, so record as best
		if (bestCaInfo == nil && bestCaAlgInfo == nil) ||
			(bestCaAlgInfo != nil && curCaAlgInfo.weighting > bestCaAlgInfo.weighting) {
			bestCaInfo = curCaInfo
			bestCaAlgInfo = curCaAlgInfo
		}
	}

	slog.Debug("selectCAInfo", "caInfo(best)", bestCaInfo, "caAlgInfo(best)", bestCaAlgInfo)

	return bestCaInfo, bestCaAlgInfo, nil
}

// infer the CA entry (based on available CA keys)
// returns: nil (caAuthInfo/caAlgInfo) if none found, otherwise CA entry
func inferCAInfoFromKey(doc *document.Document) (caInfo *document.ChipAuthenticationInfo, caAlgInfo *CaAlgorithmInfo, err error) {
	slog.Debug("inferCAInfoFromKey")

	/*
	* Some passports (e.g. FR) are missing the ca-info, so we default to 3DES
	 */

	if len(doc.Mf.Lds1.Dg14.SecInfos.ChipAuthPubKeyInfos) > 0 {
		// just go with the 1st key
		var keyInfo *document.ChipAuthenticationPublicKeyInfo = &(doc.Mf.Lds1.Dg14.SecInfos.ChipAuthPubKeyInfos[0])

		// process based on the type of key (DH/ECDH)
		if keyInfo.Protocol.Equal(oid.OidPkDh) {
			// DH
			caInfo = &document.ChipAuthenticationInfo{Protocol: oid.OidCaDh3DesCbcCbc, Version: 1}
		} else if keyInfo.Protocol.Equal(oid.OidPkEcdh) {
			// ECDH
			caInfo = &document.ChipAuthenticationInfo{Protocol: oid.OidCaEcdh3DesCbcCbc, Version: 1}
		} else {
			return nil, nil, fmt.Errorf("(inferCAInfoFromKey) unsupported key type (OID:%s)", keyInfo.Protocol.String())
		}

		caAlgInfo, err = getAlgInfo(caInfo.Protocol)
		if err != nil {
			return nil, nil, err
		}
	} else {
		slog.Debug("inferCAInfoFromKey - skip due to lack of ChipAuthPubKeyInfos")
	}

	return caInfo, caAlgInfo, nil
}

// selects the public key matching the target OID (i.e. oidPkDh / oidPkEcdh) as well as the 'KeyId' (if specified)
func selectCAPubKeyInfo(caInfo *document.ChipAuthenticationInfo, caAlgInfo *CaAlgorithmInfo, doc *document.Document) (*document.ChipAuthenticationPublicKeyInfo, error) {
	for i := range doc.Mf.Lds1.Dg14.SecInfos.ChipAuthPubKeyInfos {
		var curPubKey *document.ChipAuthenticationPublicKeyInfo = &(doc.Mf.Lds1.Dg14.SecInfos.ChipAuthPubKeyInfos[i])

		if curPubKey.Protocol.Equal(caAlgInfo.targetOid) {
			// no key-id specified, so good to use any matching public-key
			// *OR* key-id specified, so need to find matching public-key
			if (caInfo.KeyId == nil) ||
				((caInfo.KeyId != nil) && (caInfo.KeyId.Cmp(curPubKey.KeyId) == 0)) {
				return curPubKey, nil
			}
		}
	}

	return nil, fmt.Errorf("chipAuth: unable to locate public key (oid:%s) (keyId:%s)", caAlgInfo.targetOid.String(), caInfo.KeyId)
}

type CaAlgorithmInfo struct {
	targetOid   asn1.ObjectIdentifier
	cipherAlg   cryptoutils.BlockCipherAlg
	keySizeBits int
	weighting   int
}

// NB weighting: we prioritise ECDH (2xxx) over DH (1xxx), then select based on key-bits
var caAlgInfo = map[string]CaAlgorithmInfo{
	oid.OidCaDh3DesCbcCbc.String():    {oid.OidPkDh, cryptoutils.TDES, 112, 1112},
	oid.OidCaDhAesCbcCmac128.String(): {oid.OidPkDh, cryptoutils.AES, 128, 1128},
	oid.OidCaDhAesCbcCmac192.String(): {oid.OidPkDh, cryptoutils.AES, 192, 1192},
	oid.OidCaDhAesCbcCmac256.String(): {oid.OidPkDh, cryptoutils.AES, 256, 1256},

	oid.OidCaEcdh3DesCbcCbc.String():    {oid.OidPkEcdh, cryptoutils.TDES, 112, 2112},
	oid.OidCaEcdhAesCbcCmac128.String(): {oid.OidPkEcdh, cryptoutils.AES, 128, 2128},
	oid.OidCaEcdhAesCbcCmac192.String(): {oid.OidPkEcdh, cryptoutils.AES, 192, 2192},
	oid.OidCaEcdhAesCbcCmac256.String(): {oid.OidPkEcdh, cryptoutils.AES, 256, 2256},
}

func getAlgInfo(oid asn1.ObjectIdentifier) (*CaAlgorithmInfo, error) {
	out, ok := caAlgInfo[oid.String()]

	if !ok {
		return nil, fmt.Errorf("getAlgInfo: OID not found (%s)", oid.String())
	}

	return &out, nil
}

func (chipAuth *ChipAuth) doMseSetAT(nfc *iso7816.NfcSession, caInfo *document.ChipAuthenticationInfo) error {
	// MSE:Set AT
	//
	// INS: 0x22
	// P1/P2: 0x41A4
	// Data: 0x80 - OID of protocol (mandatory)			<-- caInfo.Protocol
	//		 0x84 - KeyId			(conditional)		<-- if multiple public keys are available
	//
	// Exp Rsp: 9000
	//			Exp errors: 6A80 / 6A88 / ...

	slog.Debug("doCaECdh - doMseSetAT")

	nodes := tlv.NewTlvNodes()

	nodes.AddNode(tlv.NewTlvSimpleNode(0x80, oid.OidBytes(caInfo.Protocol)))
	// specify key-id (if required)
	if caInfo.KeyId != nil {
		nodes.AddNode(tlv.NewTlvSimpleNode(0x84, caInfo.KeyId.Bytes()))
	}

	// MSE:Set AT (0x41A4: Chip Authentication)
	err := nfc.MseSetAT(0x41, 0xA4, nodes.Encode())

	return err
}

func (chipAuth *ChipAuth) doGeneralAuthenticate(nfc *iso7816.NfcSession, curve *elliptic.Curve, termKeypair cryptoutils.EcKeypair, chipPubKey *cryptoutils.EcPoint, caAlgInfo *CaAlgorithmInfo) (ksEnc []byte, ksMac []byte, err error) {
	// General Authenticate
	//
	// INS: 0x86
	// P1/P2: 0x0000
	// Data: 0x7C - Dynamic Authentication Data
	//			0x80 - Ephemeral Public Key				<-- termPub
	//
	// Exp Rsp: 9000
	//			+ 0x7C - Dynamic Authentication Data
	//			Exp errors: 6300 / 6A80 / 6A88 / ...

	slog.Debug("doGeneralAuthenticate")

	var rApdu *iso7816.RApdu = nfc.GeneralAuthenticate(false, encodeDynAuthData(0x80, cryptoutils.EncodeX962EcPoint(*curve, termKeypair.Pub)))
	if !rApdu.IsSuccess() {
		return nil, nil, fmt.Errorf("doGeneralAuthenticate: General Authenticate failed (Status:%d)", rApdu.Status)
	}

	slog.Debug("doGeneralAuthenticate", "rApdu-bytes", utils.BytesToHex(rApdu.Data))

	// verify that the response includes a 7C tag
	if !tlv.Decode(rApdu.Data).GetNode(0x7C).IsValidNode() {
		return nil, nil, fmt.Errorf("doGeneralAuthenticate: missing 7C tag in response (rspBytes:%x)", rApdu.Data)
	}

	// 3. Both the eMRTD chip and the terminal compute the following:
	// a) The shared secret K = KA(SKIC, PKDH,IFD, DIC) = KA(SKDH,IFD, PKIC, DIC)
	var k *cryptoutils.EcPoint = cryptoutils.DoEcDh(termKeypair.Pri, chipPubKey, *curve)

	// NB secret is just based on 'x'
	sharedSecret := k.X.Bytes()

	slog.Debug("doGeneralAuthenticate", "sharedSecret", utils.BytesToHex(sharedSecret))

	// b) The session keys KSMAC = KDFMAC(K) and KSEnc = KDFEnc(K) derived from K for Secure Messaging.
	ksEnc = cryptoutils.KDF(sharedSecret, cryptoutils.KDF_COUNTER_KSENC, caAlgInfo.cipherAlg, caAlgInfo.keySizeBits)
	ksMac = cryptoutils.KDF(sharedSecret, cryptoutils.KDF_COUNTER_KSMAC, caAlgInfo.cipherAlg, caAlgInfo.keySizeBits)
	slog.Debug("doGeneralAuthenticate", "ksEnc", utils.BytesToHex(ksEnc), "ksMac", utils.BytesToHex(ksMac))

	return ksEnc, ksMac, err
}

// performs Chip Authentication in ECDH mode
// NB does NOT update doc.ChipAuthStatus, caller is expected to do this!
// NB we currently implement the AES (2) APDU approach, which should also work for TDES (i.e. we don't implement MSE:Set KAT just for TDES)
func (chipAuth *ChipAuth) doCaEcdh(nfc *iso7816.NfcSession, caInfo *document.ChipAuthenticationInfo, caAlgInfo *CaAlgorithmInfo, caPubKeyInfo *document.ChipAuthenticationPublicKeyInfo) (err error) {
	slog.Debug("doCaEcdh", "OID", caInfo.Protocol.String())

	var curve *elliptic.Curve
	var chipPubKey *cryptoutils.EcPoint
	curve, chipPubKey = caPubKeyInfo.ChipAuthenticationPublicKey.GetEcCurveAndPubKey()

	slog.Debug("doCaEcdh", "chipPubKey", chipPubKey.String())

	// generate ephemeral key
	var termKeypair cryptoutils.EcKeypair = chipAuth.keyGeneratorEc(*curve)

	// TODO - still having issue with FR passport (T)
	//			- may need to support the pure TDES flow, instead of the following

	err = chipAuth.doMseSetAT(nfc, caInfo)
	if err != nil {
		return err
	}

	var ksEnc, ksMac []byte

	ksEnc, ksMac, err = chipAuth.doGeneralAuthenticate(nfc, curve, termKeypair, chipPubKey, caAlgInfo)
	if err != nil {
		return err
	}

	// setup secure-messaging
	// NB no need to set SSC for ChipAuth
	slog.Debug("doCaECdh - Setup Secure Messaging")
	{
		var err error

		nfc.SM, err = iso7816.NewSecureMessaging(caAlgInfo.cipherAlg, ksEnc, ksMac)
		if err != nil {
			return err
		}
	}

	/*
	* Chip Authentication has completed and we've setup/updated Secure Messaging accordingly
	* **BUT** we don't know whether it was really successful until we perform an APDU with the new
	* Secure Messaging, so we perform a lightweight APDU (Select EF - DG14) to confirm success.
	 */

	slog.Debug("doCaECdh - Select EF (DG14) - to verify ChipAuth")
	{
		const MRTDFileIdDG14 = uint16(0x010E)

		selected, err := nfc.SelectEF(MRTDFileIdDG14)
		if err != nil {
			return fmt.Errorf("(CA.doCaEcdh) Error selecting DG14 following ChipAuth: %w", err)
		}
		if !selected {
			return fmt.Errorf("(CA.doCaEcdh) unable to select DG14 after performing CA")
		}
	}

	return nil
}

// dynamic authentication data - (TLV) 7C <tag> <data>
func encodeDynAuthData(tag byte, data []byte) []byte {
	node := tlv.NewTlvConstructedNode(0x7C)
	node.AddChild(tlv.NewTlvSimpleNode(tlv.TlvTag(tag), data))
	return node.Encode()
}
