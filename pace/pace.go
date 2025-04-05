// Package pace supports the 'Password Authenticated Connection Establishment' (PACE) authentication protocol.
package pace

//	4.4.1 Protocol Specification
//
//	The inspection system reads the parameters for PACE supported by the eMRTD chip from the file EF.CardAccess (cf. Section 9.2.11) and selects the parameters to be used, followed by the protocol execution.
//
//	The following commands SHALL be used:
//		• READ BINARY as specified in Doc 9303-10;
//		• MSE:Set AT (MANAGE SECURITY ENVIRONMENT command with Set Authentication Template function) as specified in Section 4.4.4.1;
//
//	The following steps SHALL be performed by the inspection system and the eMRTD chip using a chain of GENERAL AUTHENTICATE commands as specified in Section 4.4.4.2:
//
//	1) The eMRTD chip randomly and uniformly chooses a nonce s, encrypts the nonce to z = E(Kπ,s), where Kπ = KDFπ (π) is derived from the shared password π, and sends the ciphertext z to the inspection system.
//	2) The inspection system recovers the plaintext s = D(Kπ,z) with the help of the shared password π.
// 	3) Both the eMRTD chip and the inspection system perform the following steps:
//  	a) They exchange additional data required for the mapping of the nonce:
//   		i) for the generic mapping, the eMRTD chip and the inspection system exchange ephemeral key public keys.
//   		ii) for the integrated mapping, the inspection system sends an additional nonce to the eMRTD chip.
//  	b) They compute the ephemeral domain parameters D = Map(DIC,s,...) as described in Section 4.4.3.3.
//  	c) They perform an anonymous Diffie-Hellman key agreement (cf. Section 9.6) based on the ephemeral domain parameters and generate the shared secret K = KA(SKDH,IC, PKDH,IFD,D) = KA(SKDH,IFD, PKDH,IC,D).
//  	d) During Diffie-Hellman key agreement, the IC and the inspection system SHOULD check that the two public keys PKDH,IC and PKDH,IFD differ.
//  	e) They derive session keys KSMAC = KDFMAC(K) and KSEnc = KDFEnc(K) as described in Section 9.7.1.
//  	f) They exchange and verify the authentication token TIFD = MAC(KSMAC,PKDH,IC) and TIC = MAC(KSMAC,PKDH,IFD) as described in Section 4.4.3.4.
// 4) Conditionally, the eMRTD chip computes Chip Authentication Data CAIC, encrypts them AIC = E(KSEnc, CAIC) and sends them to the terminal (cf. Section 4.4.3.5.1). The terminal decrypts AIC and verifies the authenticity of the chip using the recovered Chip Authentication Data CAIC (cf. Section 4.4.3.5.2).

import (
	"bytes"
	"crypto/cipher"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"log"
	"log/slog"
	"math/big"

	"github.com/aead/cmac"
	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
	"github.com/osanderson/brainpool"
)

type Pace struct {
	keyGeneratorEc cryptoutils.KeyGeneratorEcFn
	nfcSession     **iso7816.NfcSession
	document       **document.Document
	password       *password.Password
}

func NewPace(nfc *iso7816.NfcSession, doc *document.Document, pass *password.Password) *Pace {
	var pace Pace
	pace.keyGeneratorEc = cryptoutils.KeyGeneratorEc
	pace.nfcSession = &nfc
	pace.document = &doc
	pace.password = pass
	return &pace
}

type PACEMapping int

const (
	GM PACEMapping = iota
	IM
	CAM
)

type PACESeccureMessaging int

type PACEAuthToken int

const (
	CBC PACEAuthToken = iota
	CMAC
)

// NB secure-messaging is currently inferred from 'cipher'
type PaceConfig struct {
	oid           asn1.ObjectIdentifier
	mapping       PACEMapping
	cipher        cryptoutils.BlockCipherAlg
	keyLengthBits int
	authToken     PACEAuthToken
	weighting     int
}

func (cfg *PaceConfig) String() string {
	return fmt.Sprintf("(oid:%s, mapping:%d, cipher:%d, keyLenBits:%d, authToken:%d, weighting:%d)",
		cfg.oid.String(), cfg.mapping, cfg.cipher, cfg.keyLengthBits, cfg.authToken, cfg.weighting)
}

/*
	OID									Mapping					Cipher	Keylength	Secure Messaging	Auth. Token

	id-PACE-DH-GM-3DES-CBC-CBC 			Generic 				3DES 	112 		CBC / CBC 			CBC
	id-PACE-DH-GM-AES-CBC-CMAC-128 		Generic 				AES 	128 		CBC / CMAC 			CMAC
	id-PACE-DH-GM-AES-CBC-CMAC-192 		Generic 				AES 	192 		CBC / CMAC 			CMAC
	id-PACE-DH-GM-AES-CBC-CMAC-256 		Generic 				AES 	256 		CBC / CMAC 			CMAC
	id-PACE-ECDH-GM-3DES-CBC-CBC 		Generic 				3DES 	112 		CBC / CBC 			CBC
	id-PACE-ECDH-GM-AES-CBC-CMAC-128 	Generic 				AES 	128 		CBC / CMAC 			CMAC
	id-PACE-ECDH-GM-AES-CBC-CMAC-192 	Generic 				AES 	192 		CBC / CMAC 			CMAC
	id-PACE-ECDH-GM-AES-CBC-CMAC-256 	Generic 				AES 	256 		CBC / CMAC 			CMAC
	id-PACE-DH-IM-3DES-CBC-CBC 			Integrated 				3DES 	112			CBC / CBC 			CBC
	id-PACE-DH-IM-AES-CBC-CMAC-128 		Integrated 				AES 	128 		CBC / CMAC 			CMAC
	id-PACE-DH-IM-AES-CBC-CMAC-192 		Integrated 				AES 	192 		CBC / CMAC 			CMAC
	id-PACE-DH-IM-AES-CBC-CMAC-256 		Integrated 				AES 	256 		CBC / CMAC 			CMAC
	id-PACE-ECDH-IM-3DES-CBC-CBC 		Integrated 				3DES 	112 		CBC / CBC 			CBC
	id-PACE-ECDH-IM-AES-CBC-CMAC-128 	Integrated 				AES 	128 		CBC / CMAC 			CMAC
	id-PACE-ECDH-IM-AES-CBC-CMAC-192 	Integrated 				AES 	192 		CBC / CMAC 			CMAC
	id-PACE-ECDH-IM-AES-CBC-CMAC-256 	Integrated 				AES 	256 		CBC / CMAC 			CMAC
	id-PACE-ECDH-CAM-AES-CBC-CMAC-128 	Chip Authentication 	AES 	128 		CBC / CMAC 			CMAC
	id-PACE-ECDH-CAM-AES-CBC-CMAC-192 	Chip Authentication 	AES 	192 		CBC / CMAC 			CMAC
	id-PACE-ECDH-CAM-AES-CBC-CMAC-256 	Chip Authentication 	AES 	256 		CBC / CMAC 			CMAC
*/

var paceConfig = map[string]PaceConfig{

	oid.OidPaceDhGm3DesCbcCbc.String():    {oid.OidPaceDhGm3DesCbcCbc, GM, cryptoutils.TDES, 112, CBC, 200},
	oid.OidPaceDhGmAesCbcCmac128.String(): {oid.OidPaceDhGmAesCbcCmac128, GM, cryptoutils.AES, 128, CMAC, 201},
	oid.OidPaceDhGmAesCbcCmac192.String(): {oid.OidPaceDhGmAesCbcCmac192, GM, cryptoutils.AES, 192, CMAC, 202},
	oid.OidPaceDhGmAesCbcCmac256.String(): {oid.OidPaceDhGmAesCbcCmac256, GM, cryptoutils.AES, 256, CMAC, 203},

	oid.OidPaceEcdhGm3DesCbcCbc.String():    {oid.OidPaceEcdhGm3DesCbcCbc, GM, cryptoutils.TDES, 112, CBC, 250},
	oid.OidPaceEcdhGmAesCbcCmac128.String(): {oid.OidPaceEcdhGmAesCbcCmac128, GM, cryptoutils.AES, 128, CMAC, 251},
	oid.OidPaceEcdhGmAesCbcCmac192.String(): {oid.OidPaceEcdhGmAesCbcCmac192, GM, cryptoutils.AES, 192, CMAC, 252},
	oid.OidPaceEcdhGmAesCbcCmac256.String(): {oid.OidPaceEcdhGmAesCbcCmac256, GM, cryptoutils.AES, 256, CMAC, 253},

	oid.OidPaceDhIm3DesCbcCbc.String():    {oid.OidPaceDhIm3DesCbcCbc, IM, cryptoutils.TDES, 112, CBC, 100},
	oid.OidPaceDhImAesCbcCmac128.String(): {oid.OidPaceDhImAesCbcCmac128, IM, cryptoutils.AES, 128, CMAC, 101},
	oid.OidPaceDhImAesCbcCmac192.String(): {oid.OidPaceDhImAesCbcCmac192, IM, cryptoutils.AES, 192, CMAC, 102},
	oid.OidPaceDhImAesCbcCmac256.String(): {oid.OidPaceDhImAesCbcCmac256, IM, cryptoutils.AES, 256, CMAC, 103},

	oid.OidPaceEcdhIm3DesCbcCbc.String():    {oid.OidPaceEcdhIm3DesCbcCbc, IM, cryptoutils.TDES, 112, CBC, 150},
	oid.OidPaceEcdhImAesCbcCmac128.String(): {oid.OidPaceEcdhImAesCbcCmac128, IM, cryptoutils.AES, 128, CMAC, 151},
	oid.OidPaceEcdhImAesCbcCmac192.String(): {oid.OidPaceEcdhImAesCbcCmac192, IM, cryptoutils.AES, 192, CMAC, 152},
	oid.OidPaceEcdhImAesCbcCmac256.String(): {oid.OidPaceEcdhImAesCbcCmac256, IM, cryptoutils.AES, 256, CMAC, 153},

	oid.OidPaceEcdhCamAesCbcCmac128.String(): {oid.OidPaceEcdhCamAesCbcCmac128, CAM, cryptoutils.AES, 128, CMAC, 300},
	oid.OidPaceEcdhCamAesCbcCmac192.String(): {oid.OidPaceEcdhCamAesCbcCmac192, CAM, cryptoutils.AES, 192, CMAC, 301},
	oid.OidPaceEcdhCamAesCbcCmac256.String(): {oid.OidPaceEcdhCamAesCbcCmac256, CAM, cryptoutils.AES, 256, CMAC, 302},
}

type PACEDomainParams struct {
	id     int
	isECDH bool
	ec     elliptic.Curve
}

func paceConfigGetByOID(oid asn1.ObjectIdentifier) *PaceConfig {
	out, ok := paceConfig[oid.String()]

	if !ok {
		panic(fmt.Sprintf("[paceConfigGetByOID] unknown OID (%s)", oid))
	}

	return &out
}

// ICAO9303 part 11... s9.5.1 Standardized Domain Parameters
func getStandardisedDomainParams(paramId int) *PACEDomainParams {
	var ret *PACEDomainParams

	// NB 3-7 and 19-31 are RFU
	switch paramId {
	case 0:
		// 1024-bit MODP Group with 160-bit Prime Order Subgroup
		log.Panicf("PACE Standard Domain Parameter (paramId:%1d) NOT IMPLEMENTED", paramId)
	case 1:
		// 2048-bit MODP Group with 224-bit Prime Order Subgroup
		log.Panicf("PACE Standard Domain Parameter (paramId:%1d) NOT IMPLEMENTED", paramId)
	case 2:
		// 2048-bit MODP Group with 256-bit Prime Order Subgroup
		log.Panicf("PACE Standard Domain Parameter (paramId:%1d) NOT IMPLEMENTED", paramId)
	case 8:
		// NIST P-192 (secp192r1)
		ret = &PACEDomainParams{id: paramId, isECDH: true, ec: cryptoutils.EllipticP192()}
	case 9:
		// Brainpool P192r1
		ret = &PACEDomainParams{id: paramId, isECDH: true, ec: brainpool.P192r1()}
	case 10:
		// NIST P-224 (secp224r1)
		ret = &PACEDomainParams{id: paramId, isECDH: true, ec: elliptic.P224()}
	case 11:
		// Brainpool P224r1
		ret = &PACEDomainParams{id: paramId, isECDH: true, ec: brainpool.P224r1()}
	case 12:
		// NIST P-256 (secp256r1)
		ret = &PACEDomainParams{id: paramId, isECDH: true, ec: elliptic.P256()}
	case 13:
		// Brainpool P256r1
		ret = &PACEDomainParams{id: paramId, isECDH: true, ec: brainpool.P256r1()}
	case 14:
		// Brainpool P320r1
		ret = &PACEDomainParams{id: paramId, isECDH: true, ec: brainpool.P320r1()}
	case 15:
		// NIST P-384 (secp384r1)
		ret = &PACEDomainParams{id: paramId, isECDH: true, ec: elliptic.P384()}
	case 16:
		// Brainpool P384r1
		ret = &PACEDomainParams{id: paramId, isECDH: true, ec: brainpool.P384r1()}
	case 17:
		// Brainpool P512r1
		ret = &PACEDomainParams{id: paramId, isECDH: true, ec: brainpool.P512r1()}
	case 18:
		// NIST P-521 (secp521r1)
		ret = &PACEDomainParams{id: paramId, isECDH: true, ec: elliptic.P521()}
	default:
		panic(fmt.Sprintf("[getStandardisedDomainParams] Unsupported paramId (%1d)", paramId))
	}

	return ret
}

func (paceConfig *PaceConfig) decryptNonce(key []byte, encryptedNonce []byte) []byte {
	var err error
	var bcipher cipher.Block

	if bcipher, err = cryptoutils.GetCipherForKey(paceConfig.cipher, key); err != nil {
		panic(fmt.Sprintf("[decryptNonce] Unexpected error: %s", err))
	}

	iv := make([]byte, bcipher.BlockSize()) // 0'd IV

	return cryptoutils.CryptCBC(bcipher, iv, encryptedNonce, false)
}

// 4.4.3.4 Authentication Token
//
// The authentication token SHALL be computed over a public key data object (cf. Section 9.4) containing the object
// identifier as indicated in MSE:Set AT (cf. Section 4.4.4.1), and the received ephemeral public key (i.e. excluding
// the domain parameters, cf. Section 9.4.5) using an authentication code and the key KSMAC derived from the key agreement.
//
// Note.— Padding is performed internally by the message authentication code, i.e. no application specific padding is performed.
//
// 3DES
//
// 3DES [FIPS 46-3] SHALL be used in Retail-mode according to [ISO/IEC 9797-1] MAC algorithm 3 / padding method 2 with block cipher DES and IV=0.
//
// # AES
//
// AES [FIPS 197] SHALL be used in CMAC-mode [SP 800-38B] with a MAC length of 8 bytes.
func (paceConfig *PaceConfig) computeAuthToken(key []byte, data []byte) []byte {
	slog.Debug("computeAuthToken", "key", utils.BytesToHex(key), "data", utils.BytesToHex(data))

	switch paceConfig.authToken {
	case CBC:
		// CBC-mode with MAC length of 8 bytes
		// 3DES [FIPS 46-3] SHALL be used in Retail-mode according to [ISO/IEC 9797-1] MAC algorithm 3 / padding method 2 with block cipher DES and IV=0.

		if paceConfig.cipher != cryptoutils.TDES {
			panic(fmt.Sprintf("[computeAuthToken] CBC Authentication Token is only supported for 3DES (ActCipherAlg:%d)", int(paceConfig.cipher)))
		}

		var err error
		var authToken []byte

		authToken, err = cryptoutils.ISO9797RetailMacDes(key, cryptoutils.ISO9797Method2Pad(data, cryptoutils.DES_BLOCK_SIZE_BYTES))
		if err != nil {
			panic(fmt.Sprintf("[computeAuthToken] Unable to generate Auth-Token (CBC): %s", err.Error()))
		}

		slog.Debug("computeAuthToken", "authToken(CBC)", utils.BytesToHex(authToken))
		return authToken
	case CMAC:
		// CMAC-mode with MAC length of 8 bytes
		// AES [FIPS 197] SHALL be used in CMAC-mode [SP 800-38B] with a MAC length of 8 bytes.

		if paceConfig.cipher != cryptoutils.AES {
			panic(fmt.Sprintf("[computeAuthToken] CMAC Authentication Token is only supported for AES (ActCipherAlg:%d)", int(paceConfig.cipher)))
		}

		var err error
		var cipher cipher.Block

		cipher, err = cryptoutils.GetCipherForKey(paceConfig.cipher, key)
		if err != nil {
			panic(fmt.Sprintf("[computeAuthToken] Unable to get cipher (%s)", err))
		}

		authToken, err := cmac.Sum(data, cipher, 8)
		if err != nil {
			panic(fmt.Sprintf("Unable to generate Auth-Token (CMAC): %s", err.Error()))
		}

		slog.Debug("computeAuthToken", "authToken(CMAC)", utils.BytesToHex(authToken))
		return authToken
	}

	panic(fmt.Sprintf("Unsupported auth-token alg (%x)", paceConfig.authToken))

	return nil
}

// s: nonce (from chip)
// Hxy: shared secret (derived earlier from ECDH)
// ec: elliptic curve (domain parameters)
func doGenericMappingEC(s []byte, H *cryptoutils.EcPoint, ec elliptic.Curve) *cryptoutils.EcPoint {
	var sGx, sGy *big.Int

	sGx, sGy = ec.ScalarBaseMult(s)

	var out cryptoutils.EcPoint

	out.X, out.Y = ec.Add(sGx, sGy, H.X, H.Y)

	return &out
}

// dynamic authentication data - (TLV) 7C <tag> <data>
func encodeDynAuthData(tag byte, data []byte) []byte {
	node := tlv.NewTlvConstructedNode(0x7C)
	node.AddChild(tlv.NewTlvSimpleNode(tlv.TlvTag(tag), data))
	return node.Encode()
}

// dynamic authentication data - (TLV) 7C <tag> <data>
func decodeDynAuthData(tag byte, data []byte) []byte {
	tmpNodes, err := tlv.Decode(data)
	if err != nil {
		panic(fmt.Sprintf("[decodeDynAuthData] tlv.Decode error: %s", err))
	}
	return tmpNodes.GetNode(0x7C).GetNode(tlv.TlvTag(tag)).GetValue()
}

// encodes a public-key template (7F49) containing the OID and the public-key (86)
// NB caller should ensure that tag86data is encoded correctly for the underlying key type (DH/ECDH)
func encodePubicKeyTemplate7F49(paceOid []byte, tag86data []byte) []byte {
	// 7F49
	//		06 - OID
	//		86 - Uncompressed EC point (x/y)

	node := tlv.NewTlvConstructedNode(0x7F49)
	node.AddChild(tlv.NewTlvSimpleNode(0x06, paceOid))
	node.AddChild(tlv.NewTlvSimpleNode(0x86, tag86data))

	return node.Encode()
}

func (pace *Pace) doApduMsgSetAT(paceConfig *PaceConfig) (err error) {
	slog.Debug("doApduMsgSetAT")

	paceOidBytes := oid.OidBytes(paceConfig.oid)

	nodes := tlv.NewTlvNodes()
	nodes.AddNode(tlv.NewTlvSimpleNode(0x80, paceOidBytes))
	nodes.AddNode(tlv.NewTlvSimpleNode(0x83, []byte{pace.password.GetType()}))

	// MSE:Set AT (0xC1A4: Set Authentication Template for mutual authentication)
	err = (*pace.nfcSession).MseSetAT(0xC1, 0xA4, nodes.Encode())
	if err != nil {
		return err
	}

	return nil
}

// mapNonce(GM-EC)
//   - creates keypair
//   - exchanges with chip
//   - generates shared secret
//   - do generic mapping (and return G)
func (pace *Pace) mapNonceGmEcDh(domainParams *PACEDomainParams, s []byte) (mapped_g *cryptoutils.EcPoint, pubMapIC *cryptoutils.EcPoint) {
	slog.Debug("mapNonceGmEcDh", "s", utils.BytesToHex(s))

	// generate terminal key (private/public)
	var termKeypair cryptoutils.EcKeypair = pace.keyGeneratorEc(domainParams.ec)

	// do public-key exchange to get chip pub-key
	{
		reqData := encodeDynAuthData(0x81, cryptoutils.EncodeX962EcPoint(domainParams.ec, termKeypair.Pub))

		rApdu := (*pace.nfcSession).GeneralAuthenticate(true, reqData)
		if !rApdu.IsSuccess() {
			log.Panicf("Error mapping the nonce - GM-EC (Status:%x)", rApdu.Status)
		}

		pubMapIC = cryptoutils.DecodeX962EcPoint(domainParams.ec, decodeDynAuthData(0x82, rApdu.Data))
		slog.Debug("mapNonceGmEcDh", "pubMapIC", pubMapIC.String())
	}

	//
	// Shared Secret H
	//
	var termShared *cryptoutils.EcPoint = cryptoutils.DoEcDh(termKeypair.Pri, pubMapIC, domainParams.ec)
	slog.Debug("mapNonceGmEcDh", "termShared", termShared.String())

	//
	// Mapped G
	//
	mapped_g = doGenericMappingEC(s, termShared, domainParams.ec)

	return mapped_g, pubMapIC
}

func (pace *Pace) keyAgreementGmEcDh(domainParams *PACEDomainParams, G *cryptoutils.EcPoint) (sharedSecret []byte, termKeypair cryptoutils.EcKeypair, chipPub *cryptoutils.EcPoint) {
	// reader and chip generate/exchange another set of public-keys
	//			- needs to be generated using mapped-g.x/y
	//			- new keys for terminal
	//			- exchange to get chip keys

	slog.Debug("keyAgreementGmEcDh", "Gx", utils.BytesToHex(domainParams.ec.Params().Gx.Bytes()), "Gy", utils.BytesToHex(domainParams.ec.Params().Gy.Bytes()))

	// generate key based on domain-params
	// NB ignore public-key as we'll generate later using the mapped generator (Gx/y)
	termKeypair = pace.keyGeneratorEc(domainParams.ec)
	termKeypair.Pub = new(cryptoutils.EcPoint) // reset public-key

	// generate the public-key, using the mapped generator (Gxy)
	termKeypair.Pub.X, termKeypair.Pub.Y = domainParams.ec.ScalarMult(G.X, G.Y, termKeypair.Pri)

	slog.Debug("keyAgreementGmEcDh", "termKeypair", termKeypair.String())

	// exchange terminal public-key with chip and get chip's public-key
	{
		reqData := encodeDynAuthData(0x83, cryptoutils.EncodeX962EcPoint(domainParams.ec, termKeypair.Pub))

		rApdu := (*pace.nfcSession).GeneralAuthenticate(true, reqData)
		if !rApdu.IsSuccess() {
			log.Panicf("Error performing key agreement - GM-ECDH (Status:%x)", rApdu.Status)
		}

		chipPub = cryptoutils.DecodeX962EcPoint(domainParams.ec, decodeDynAuthData(0x84, rApdu.Data))
	}

	// verify the terminal and chip public-keys are not the same
	// 9303p11 4.4.1 d) During Diffie-Hellman key agreement, the IC and the inspection system SHOULD check that the two public keys PKDH,IC and PKDH,IFD differ.
	if termKeypair.Pub.Equal(*chipPub) {
		log.Panicf("terminal and chip public-keys must not be the same (Term:%s) (Chip:%s)", termKeypair.Pub.String(), chipPub.String())
	}

	{
		var termShared *cryptoutils.EcPoint = cryptoutils.DoEcDh(termKeypair.Pri, chipPub, domainParams.ec)

		// NB secret is just based on 'x'
		sharedSecret = termShared.X.Bytes()

		slog.Debug("keyAgreementGmEcDh", "shared-secret", utils.BytesToHex(sharedSecret))
	}

	return sharedSecret, termKeypair, chipPub
}

// performs mutual authentication and sets up secure messaging
// ecadIC: only populated for CAM
func (pace *Pace) mutualAuthGmEcDh(paceConfig *PaceConfig, domainParams *PACEDomainParams, sharedSecret []byte, termPub *cryptoutils.EcPoint, chipPub *cryptoutils.EcPoint) (ecadIC []byte) {
	// derive KSenc / KSmac
	var ksEnc, ksMac []byte
	ksEnc = cryptoutils.KDF(sharedSecret, cryptoutils.KDF_COUNTER_KSENC, paceConfig.cipher, paceConfig.keyLengthBits)
	ksMac = cryptoutils.KDF(sharedSecret, cryptoutils.KDF_COUNTER_KSMAC, paceConfig.cipher, paceConfig.keyLengthBits)
	slog.Debug("mutualAuthGmEcDh", "ksEnc", utils.BytesToHex(ksEnc), "ksMac", utils.BytesToHex(ksMac))

	// generate auth tokens
	var tIfd, tIc []byte
	{
		oidBytes := oid.OidBytes(paceConfig.oid)

		tIfdData := encodePubicKeyTemplate7F49(oidBytes, cryptoutils.EncodeX962EcPoint(domainParams.ec, chipPub))
		tIcData := encodePubicKeyTemplate7F49(oidBytes, cryptoutils.EncodeX962EcPoint(domainParams.ec, termPub))

		// generate auth tokens
		tIfd = paceConfig.computeAuthToken(ksMac, tIfdData)
		tIc = paceConfig.computeAuthToken(ksMac, tIcData)
	}

	// exchange/verify auth tokens (tifd/tic) with passport
	{
		reqData := encodeDynAuthData(0x85, tIfd)

		rApdu := (*pace.nfcSession).GeneralAuthenticate(false, reqData)
		if !rApdu.IsSuccess() {
			log.Panicf("Error exchanging auth tokens (Status:%x)", rApdu.Status)
		}

		tIc2 := decodeDynAuthData(0x86, rApdu.Data)

		// verify that chip responded with the expected 'tIC' value
		if !bytes.Equal(tIc2, tIc) {
			log.Panicf("Incorrect TIC returned by chip\n[Exp] %x\n[Act] %x", tIc, tIc2)
		}

		// get Encrypted Chip Authentication Data' (tag:8A) if CAM
		// Encrypted Chip Authentication Data (cf. Section 4.4.3.5) MUST be present if Chip Authentication Mapping is used and MUST NOT be present otherwise.
		if paceConfig.mapping == CAM {
			ecadIC = decodeDynAuthData(0x8A, rApdu.Data)
			if len(ecadIC) < 1 {
				log.Panicf("Encrypted Chip Authentication Data (Tag:8A) is mandatory for PACE CAM")
			}
		}
	}

	// setup secure messaging
	{
		var err error
		if (*pace.nfcSession).SM, err = iso7816.NewSecureMessaging(paceConfig.cipher, ksEnc, ksMac); err != nil {
			log.Panicf("Error setting up Secure Messaging: %s", err)
		}
	}

	return ecadIC
}

func getIcPubKeyECForCAM(domainParams *PACEDomainParams, cardSecurity *document.CardSecurity) *cryptoutils.EcPoint {
	slog.Debug("getIcPubKeyECForCAM")

	var caPubKeyInfos []document.ChipAuthenticationPublicKeyInfo = cardSecurity.SecurityInfos.ChipAuthPubKeyInfos

	if !domainParams.isECDH {
		log.Panicf("Cannot get EC public key for !EC crypto")
	}

	for i := range caPubKeyInfos {
		var subjectPubKeyInfo *cms.SubjectPublicKeyInfo = &caPubKeyInfos[i].ChipAuthenticationPublicKey

		if !subjectPubKeyInfo.Algorithm.Algorithm.Equal(oid.OidBsiDeEcKeyType) {
			log.Panicf("(getIcPubKeyECForCAM) Wrong OID (act:%s)", subjectPubKeyInfo.Algorithm.Algorithm.String())
		}

		if utils.BytesToInt(subjectPubKeyInfo.Algorithm.Parameters.Bytes) == domainParams.id {
			var tmpKey []byte = subjectPubKeyInfo.SubjectPublicKey.Bytes
			return cryptoutils.DecodeX962EcPoint(domainParams.ec, tmpKey)
		}

	}

	log.Panicf("Unable to get Public-Key for CAM")

	return nil
}

// pubMapIC: IC Public Key from earlier mapping operation
// ecadIC: encrypted chip authentication data (tag:8A) from 'mutual auth' response
func (pace *Pace) doCamEcdh(paceConfig *PaceConfig, domainParams *PACEDomainParams, pubMapIC *cryptoutils.EcPoint, ecadIC []byte) {
	if paceConfig.mapping != CAM {
		log.Panicf("Unexpected mapping during CAM processing (Mapping:%d)", paceConfig.mapping)
	}
	if len(ecadIC) < 1 {
		log.Panicf("ECAD missing")
	}

	slog.Debug("doCamEcdh", "ECAD-IC", utils.BytesToHex(ecadIC))

	// ICAO9303 p11... 4.4.3.3.3 Chip Authentication Mapping

	blockCipher, err := cryptoutils.GetCipherForKey(paceConfig.cipher, (*pace.nfcSession).SM.GetKsEnc())
	if err != nil {
		log.Panicf("Unexpected error: %s", err)
	}

	// IV = K(KSenc,-1)
	var iv []byte = make([]byte, blockCipher.BlockSize())
	blockCipher.Encrypt(iv, bytes.Repeat([]byte{0xff}, blockCipher.BlockSize()))

	// decrypt the data we got earlier...
	var caIC []byte = cryptoutils.ISO9797Method2Unpad(cryptoutils.CryptCBC(blockCipher, iv, ecadIC, false))
	slog.Debug("doCamEcdh", "CA-IC", utils.BytesToHex(caIC))

	// 4.4.3.5.2 Verification by the terminal
	// The terminal SHALL decrypt AIC to recover CAIC and verify PKMap,IC = KA(CAIC, PKIC, DIC), where PKIC is the static public
	// key of the eMRTD chip.
	// t_ic_dcad --> CAic

	// NB we assume that CAM needs to use the same domain-params as used earlier, so we scan card-security file
	//    to find a key that matches the param-id

	// get IC PubKey (EC) for paramId
	var pkIC *cryptoutils.EcPoint = getIcPubKeyECForCAM(domainParams, (*pace.document).Mf.CardSecurity)

	var KA *cryptoutils.EcPoint = cryptoutils.DoEcDh(caIC, pkIC, domainParams.ec)
	slog.Debug("doCamEcdh", "KA", KA.String())

	// Verify that PKMAP,IC = KA(CAIC, PKIC, DIC).
	if !KA.Equal(*pubMapIC) {
		log.Panicf("PACE CAM verification failed (Bad KA.X/Y) KA:%s, pubMapIC:%s", KA.String(), pubMapIC.String())
	}

	// record that Chip Auth has been performed using PACE-CAM
	(*pace.document).ChipAuthStatus = document.CHIP_AUTH_STATUS_PACE_CAM
}

func getKeyForPassword(paceConfig *PaceConfig, pass *password.Password) []byte {
	return cryptoutils.KDF(pass.GetKey(), cryptoutils.KDF_COUNTER_PACE, paceConfig.cipher, paceConfig.keyLengthBits)
}

func (pace *Pace) getNonce(paceConfig *PaceConfig, kKdf []byte) []byte {
	var nonceE []byte
	{
		reqData := []byte{0x7C, 0x00}
		rApdu := (*pace.nfcSession).GeneralAuthenticate(true, reqData)
		if !rApdu.IsSuccess() {
			// TODO -this is firing for NZ.. maxRead=65536... RAPDU=6982
			//			- maybe we can include this as a catch.. and try to decrease max-read
			//			** needs to be handled somewhere common like doAPDU
			log.Panicf("getNonce error (Status:%x)", rApdu.Status)
		}

		nonceE = decodeDynAuthData(0x80, rApdu.Data)
	}

	// decrypt the nonce (s)
	return paceConfig.decryptNonce(kKdf, nonceE)
}

// selects the preferred pace-config based on the options advertised in the card-access file
func selectPaceConfig(cardAccess *document.CardAccess) (paceConfig *PaceConfig, domainParams *PACEDomainParams) {
	slog.Debug("selectPaceConfig")

	var paceInfos []document.PaceInfo = cardAccess.SecurityInfos.PaceInfos

	// evaluate all entries and select the preferred, based on the associated weighting
	var selPaceInfo *document.PaceInfo
	{
		for i := range paceInfos {
			slog.Debug("selectPaceConfig", "paceInfo", paceInfos[i])

			if selPaceInfo == nil {
				selPaceInfo = &paceInfos[i]
				paceConfig = paceConfigGetByOID(selPaceInfo.Protocol)
			} else {
				tmpPaceConfig := paceConfigGetByOID(paceInfos[i].Protocol)

				if tmpPaceConfig.weighting > paceConfig.weighting {
					selPaceInfo = &paceInfos[i]
					paceConfig = tmpPaceConfig
				}
			}
		}
	}

	if selPaceInfo == nil {
		log.Panicf("No supported PACE INFO")
	}

	if selPaceInfo.ParameterId == nil {
		log.Panicf("Missing ParameterId in PaceInfo")
	}
	domainParams = getStandardisedDomainParams(int(selPaceInfo.ParameterId.Int64()))

	return paceConfig, domainParams
}

func (pace *Pace) doGenericMappingCAM(paceConfig *PaceConfig, domainParams *PACEDomainParams, s []byte) (err error) {
	switch domainParams.isECDH {
	case true: // ECDH
		// map the nonce
		var mappedG, pubMapIC *cryptoutils.EcPoint
		mappedG, pubMapIC = pace.mapNonceGmEcDh(domainParams, s)

		// Perform Key Agreement
		var sharedSecret []byte
		var kaTermKeypair cryptoutils.EcKeypair
		var kaChipPub *cryptoutils.EcPoint
		sharedSecret, kaTermKeypair, kaChipPub = pace.keyAgreementGmEcDh(domainParams, mappedG)

		var ecadIC []byte
		ecadIC = pace.mutualAuthGmEcDh(paceConfig, domainParams, sharedSecret, kaTermKeypair.Pub, kaChipPub)

		// Perform Chip Authentication (if applicable)
		if paceConfig.mapping == CAM {
			slog.Debug("doGenericMappingCAM - reading CardSecurity")

			// attempt to read CardSecurity (if we don't already have it)
			if (*pace.document).Mf.CardSecurity == nil {
				const MRTDFileIdCardSecurity = uint16(0x011D)

				(*pace.document).Mf.CardSecurity, err = document.NewCardSecurity((*pace.nfcSession).ReadFile(MRTDFileIdCardSecurity))
				if err != nil {
					return err
				}
			}

			if (*pace.document).Mf.CardSecurity == nil {
				return fmt.Errorf("cannot proceed with PACE-CAM without CardSecurity file")
			}

			pace.doCamEcdh(paceConfig, domainParams, pubMapIC, ecadIC)
		}
	case false: // DH
		return fmt.Errorf("PACE GM (DH) NOT IMPLEMENTED")
	}

	return nil
}

func (pace *Pace) DoPACE() (err error) {
	slog.Debug("DoPACE", "password-type", pace.password.PasswordType, "password", pace.password.Password)

	// PACE requires card-access
	if (*pace.document).Mf.CardAccess == nil {
		slog.Debug("DoPACE - SKIPPING as no CardAccess file is present")
		return nil
	}

	var paceConfig *PaceConfig
	var domainParams *PACEDomainParams

	// TODO - currently the following will panic if there are no pace-infos... shouldn't we just skip?
	paceConfig, domainParams = selectPaceConfig((*pace.document).Mf.CardAccess)

	slog.Debug("DoPace", "selected paceConfig", paceConfig.String())

	var kKdf []byte = getKeyForPassword(paceConfig, pace.password)

	// init PACE (via 'MSE:Set AT' command)
	// TODO - aren't there some cases where we need to specified the domain params? (i.e. multiple entries)
	if err = pace.doApduMsgSetAT(paceConfig); err != nil {
		return err
	}

	// get nonce
	var s []byte = pace.getNonce(paceConfig, kKdf)

	// process based on the mapping type (GM/IM/CAM) and the key type (ECDH/DH)
	switch paceConfig.mapping {
	case GM, CAM:
		err = pace.doGenericMappingCAM(paceConfig, domainParams, s)
		if err != nil {
			return err
		}
	case IM:
		return fmt.Errorf("PACE IM NOT IMPLEMENTED")
	}

	slog.Debug("DoPACE - Completed", "SM", (*pace.nfcSession).SM.String())

	return nil
}
