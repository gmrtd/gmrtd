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

func paceConfigGetByOID(oid asn1.ObjectIdentifier) (*PaceConfig, error) {
	out, ok := paceConfig[oid.String()]

	if !ok {
		return nil, fmt.Errorf("[paceConfigGetByOID] unknown OID (%s)", oid)
	}

	return &out, nil
}

// selects the preferred pace-config based on the options advertised in the card-access file
func selectPaceConfig(cardAccess *document.CardAccess) (*PaceConfig, *PACEDomainParams, error) {
	slog.Debug("selectPaceConfig: evaluating PACE configs")

	if cardAccess == nil || cardAccess.SecurityInfos == nil || len(cardAccess.SecurityInfos.PaceInfos) < 1 {
		return nil, nil, fmt.Errorf("[selectPaceConfig] invalid cardAccess: missing CardAccess or SecurityInfos or PaceInfos")
	}

	var selectedPaceInfo *document.PaceInfo
	var selectedConfig *PaceConfig

	for i := range cardAccess.SecurityInfos.PaceInfos {
		paceInfo := &cardAccess.SecurityInfos.PaceInfos[i]
		slog.Debug("selectPaceConfig: evaluating paceInfo", "protocol", paceInfo.Protocol)

		config, err := paceConfigGetByOID(paceInfo.Protocol)
		if err != nil {
			// TODO - we probably want to log this somewhere..
			slog.Warn("selectPaceConfig: skipping unsupported PACE protocol", "protocol", paceInfo.Protocol, "error", err)
			continue
		}

		if selectedConfig == nil || config.weighting > selectedConfig.weighting {
			selectedPaceInfo = paceInfo
			selectedConfig = config
		}
	}

	if selectedPaceInfo == nil || selectedConfig == nil {
		return nil, nil, fmt.Errorf("[selectPaceConfig] no supported PACE info found")
	}

	if selectedPaceInfo.ParameterId == nil {
		return nil, nil, fmt.Errorf("[selectPaceConfig] missing ParameterId in selected PACE info")
	}

	domainParams := getStandardisedDomainParams(int(selectedPaceInfo.ParameterId.Int64()))

	return selectedConfig, domainParams, nil
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

func (pace *Pace) doApduMseSetAT(paceConfig *PaceConfig, domainParams *PACEDomainParams) (err error) {
	slog.Debug("doApduMseSetAT")

	paceOidBytes := oid.OidBytes(paceConfig.oid)

	nodes := tlv.NewTlvNodes()
	nodes.AddNode(tlv.NewTlvSimpleNode(0x80, paceOidBytes))
	nodes.AddNode(tlv.NewTlvSimpleNode(0x83, []byte{pace.password.GetType()}))
	// this should be CONDITIONAL and only provided where there is ambiguity, but
	// we've seen some passports that always expect this to be provided
	nodes.AddNode(tlv.NewTlvSimpleNode(0x84, []byte{byte(domainParams.id)}))

	// MSE:Set AT (0xC1A4: Set Authentication Template for mutual authentication)
	err = (*pace.nfcSession).MseSetAT(0xC1, 0xA4, nodes.Encode())
	if err != nil {
		return fmt.Errorf("[doApduMseSetAT] MseSetAT error: %w", err)
	}

	return nil
}

// mapNonce(GM-EC)
//   - creates keypair
//   - exchanges with chip
//   - generates shared secret
//   - do generic mapping (and return G)
func (pace *Pace) mapNonceGmEcDh(domainParams *PACEDomainParams, s []byte) (mapped_g *cryptoutils.EcPoint, pubMapIC *cryptoutils.EcPoint, err error) {
	slog.Debug("mapNonceGmEcDh", "s", utils.BytesToHex(s))

	// generate terminal key (private/public)
	var termKeypair cryptoutils.EcKeypair = pace.keyGeneratorEc(domainParams.ec)

	// do public-key exchange to get chip pub-key
	{
		reqData := encodeDynAuthData(0x81, cryptoutils.EncodeX962EcPoint(domainParams.ec, termKeypair.Pub))

		rApduBytes, err := (*pace.nfcSession).GeneralAuthenticate(true, reqData)
		if err != nil {
			return nil, nil, fmt.Errorf("[mapNonceGmEcDh] GeneralAuthenticate error: %w", err)
		}

		pubMapIC = cryptoutils.DecodeX962EcPoint(domainParams.ec, decodeDynAuthData(0x82, rApduBytes))
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

	return mapped_g, pubMapIC, nil
}

func (pace *Pace) keyAgreementGmEcDh(domainParams *PACEDomainParams, G *cryptoutils.EcPoint) (sharedSecret []byte, termKeypair *cryptoutils.EcKeypair, chipPub *cryptoutils.EcPoint, err error) {
	// reader and chip generate/exchange another set of public-keys
	//			- needs to be generated using mapped-g.x/y
	//			- new keys for terminal
	//			- exchange to get chip keys

	slog.Debug("keyAgreementGmEcDh", "Gx", utils.BytesToHex(domainParams.ec.Params().Gx.Bytes()), "Gy", utils.BytesToHex(domainParams.ec.Params().Gy.Bytes()))

	// generate key based on domain-params
	// NB ignore public-key as we'll generate later using the mapped generator (Gx/y)
	{
		tmpTermKeypair := pace.keyGeneratorEc(domainParams.ec)
		termKeypair = &tmpTermKeypair
	}
	termKeypair.Pub = new(cryptoutils.EcPoint) // reset public-key

	// generate the public-key, using the mapped generator (Gxy)
	termKeypair.Pub.X, termKeypair.Pub.Y = domainParams.ec.ScalarMult(G.X, G.Y, termKeypair.Pri)

	slog.Debug("keyAgreementGmEcDh", "termKeypair", termKeypair.String())

	// exchange terminal public-key with chip and get chip's public-key
	{
		reqData := encodeDynAuthData(0x83, cryptoutils.EncodeX962EcPoint(domainParams.ec, termKeypair.Pub))

		rApduBytes, err := (*pace.nfcSession).GeneralAuthenticate(true, reqData)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("[keyAgreementGmEcDh] GeneralAuthenticate error: %w", err)
		}

		chipPub = cryptoutils.DecodeX962EcPoint(domainParams.ec, decodeDynAuthData(0x84, rApduBytes))
	}

	// verify the terminal and chip public-keys are not the same
	// 9303p11 4.4.1 d) During Diffie-Hellman key agreement, the IC and the inspection system SHOULD check that the two public keys PKDH,IC and PKDH,IFD differ.
	if termKeypair.Pub.Equal(*chipPub) {
		return nil, nil, nil, fmt.Errorf("[keyAgreementGmEcDh] terminal and chip public-keys must not be the same (Term:%s) (Chip:%s)", termKeypair.Pub.String(), chipPub.String())
	}

	{
		var termShared *cryptoutils.EcPoint = cryptoutils.DoEcDh(termKeypair.Pri, chipPub, domainParams.ec)

		// NB secret is just based on 'x'
		sharedSecret = termShared.X.Bytes()

		slog.Debug("keyAgreementGmEcDh", "shared-secret", utils.BytesToHex(sharedSecret))
	}

	return sharedSecret, termKeypair, chipPub, nil
}

// performs mutual authentication and sets up secure messaging
// ecadIC: only populated for CAM
func (pace *Pace) mutualAuthGmEcDh(paceConfig *PaceConfig, domainParams *PACEDomainParams, sharedSecret []byte, termPub *cryptoutils.EcPoint, chipPub *cryptoutils.EcPoint) (ecadIC []byte, err error) {
	// derive KSenc / KSmac
	var ksEnc, ksMac []byte
	ksEnc = cryptoutils.KDF(sharedSecret, cryptoutils.KDF_COUNTER_KSENC, paceConfig.cipher, paceConfig.keyLengthBits)
	ksMac = cryptoutils.KDF(sharedSecret, cryptoutils.KDF_COUNTER_KSMAC, paceConfig.cipher, paceConfig.keyLengthBits)
	slog.Debug("mutualAuthGmEcDh", "ksEnc", utils.BytesToHex(ksEnc), "ksMac", utils.BytesToHex(ksMac))

	// generate auth tokens
	var tIfd, tIc []byte
	tIfd, tIc, err = paceConfig.computeAuthTokens(ksMac, domainParams.ec, termPub, chipPub)
	if err != nil {
		return nil, fmt.Errorf("[mutualAuthGmEcDh] computeAuthTokens error: %w", err)
	}

	// exchange/verify auth tokens (tifd/tic) with passport
	{
		reqData := encodeDynAuthData(0x85, tIfd)

		rApduBytes, err := (*pace.nfcSession).GeneralAuthenticate(false, reqData)
		if err != nil {
			return nil, fmt.Errorf("[mutualAuthGmEcDh] GeneralAuthenticate error: %w", err)
		}

		tIc2 := decodeDynAuthData(0x86, rApduBytes)

		// verify that chip responded with the expected 'tIC' value
		if !bytes.Equal(tIc2, tIc) {
			return nil, fmt.Errorf("[mutualAuthGmEcDh] Incorrect TIC returned by chip\n[Exp] %x\n[Act] %x", tIc, tIc2)
		}

		// get Encrypted Chip Authentication Data' (tag:8A) if CAM
		// Encrypted Chip Authentication Data (cf. Section 4.4.3.5) MUST be present if Chip Authentication Mapping is used and MUST NOT be present otherwise.
		if paceConfig.mapping == CAM {
			ecadIC = decodeDynAuthData(0x8A, rApduBytes)
			if len(ecadIC) < 1 {
				return nil, fmt.Errorf("[mutualAuthGmEcDh] Encrypted Chip Authentication Data (Tag:8A) is mandatory for PACE CAM")
			}
		}
	}

	// setup secure messaging
	{
		var err error
		if (*pace.nfcSession).SM, err = iso7816.NewSecureMessaging(paceConfig.cipher, ksEnc, ksMac); err != nil {
			return nil, fmt.Errorf("[mutualAuthGmEcDh] NewSecureMessaging error: %w", err)
		}
	}

	return ecadIC, nil
}

func getIcPubKeyECForCAM(domainParams *PACEDomainParams, cardSecurity *document.CardSecurity) (*cryptoutils.EcPoint, error) {
	slog.Debug("getIcPubKeyECForCAM")

	var caPubKeyInfos []document.ChipAuthenticationPublicKeyInfo = cardSecurity.SecurityInfos.ChipAuthPubKeyInfos

	if !domainParams.isECDH {
		return nil, fmt.Errorf("[getIcPubKeyECForCAM] Cannot get EC public key for !EC crypto")
	}

	for i := range caPubKeyInfos {
		var subjectPubKeyInfo *cms.SubjectPublicKeyInfo = &caPubKeyInfos[i].ChipAuthenticationPublicKey

		// only evaluate EC keys
		if subjectPubKeyInfo.Algorithm.Algorithm.Equal(oid.OidBsiDeEcKeyType) {
			if utils.BytesToInt(subjectPubKeyInfo.Algorithm.Parameters.Bytes) == domainParams.id {
				var tmpKey []byte = subjectPubKeyInfo.SubjectPublicKey.Bytes
				return cryptoutils.DecodeX962EcPoint(domainParams.ec, tmpKey), nil
			}
		}
	}

	return nil, fmt.Errorf("[getIcPubKeyECForCAM] Unable to get Public-Key for CAM")
}

// pubMapIC: IC Public Key from earlier mapping operation
// ecadIC: encrypted chip authentication data (tag:8A) from 'mutual auth' response
func (pace *Pace) doCamEcdh(paceConfig *PaceConfig, domainParams *PACEDomainParams, pubMapIC *cryptoutils.EcPoint, ecadIC []byte) (err error) {
	if paceConfig.mapping != CAM {
		return fmt.Errorf("[doCamEcdh] Unexpected mapping during CAM processing (Mapping:%d)", paceConfig.mapping)
	}
	if len(ecadIC) < 1 {
		return fmt.Errorf("[doCamEcdh] ECAD missing")
	}

	slog.Debug("doCamEcdh", "ECAD-IC", utils.BytesToHex(ecadIC))

	// ICAO9303 p11... 4.4.3.3.3 Chip Authentication Mapping

	var blockCipher cipher.Block
	blockCipher, err = cryptoutils.GetCipherForKey(paceConfig.cipher, (*pace.nfcSession).SM.GetKsEnc())
	if err != nil {
		return fmt.Errorf("[doCamEcdh] GetCipherForKey error: %w", err)
	}

	// IV = K(KSenc,-1)
	var iv []byte = make([]byte, blockCipher.BlockSize())
	// Note: suppress secure mode and padding scheme warning in sonar
	//		 - this is required for CAM ECDH to generate the IV
	blockCipher.Encrypt(iv, bytes.Repeat([]byte{0xff}, blockCipher.BlockSize())) // NOSONAR

	// decrypt the data we got earlier...
	var caIC []byte
	caIC, err = cryptoutils.ISO9797Method2Unpad(cryptoutils.CryptCBC(blockCipher, iv, ecadIC, false))
	if err != nil {
		return fmt.Errorf("[doCamEcdh] ISO9797Method2Unpad error: %w", err)
	}
	slog.Debug("doCamEcdh", "CA-IC", utils.BytesToHex(caIC))

	// 4.4.3.5.2 Verification by the terminal
	// The terminal SHALL decrypt AIC to recover CAIC and verify PKMap,IC = KA(CAIC, PKIC, DIC), where PKIC is the static public
	// key of the eMRTD chip.
	// t_ic_dcad --> CAic

	// NB we assume that CAM needs to use the same domain-params as used earlier, so we scan card-security file
	//    to find a key that matches the param-id

	// get IC PubKey (EC) for paramId
	var pkIC *cryptoutils.EcPoint
	pkIC, err = getIcPubKeyECForCAM(domainParams, (*pace.document).Mf.CardSecurity)
	if err != nil {
		return fmt.Errorf("[doCamEcdh] getIcPubKeyECForCAM error: %w", err)
	}

	var KA *cryptoutils.EcPoint = cryptoutils.DoEcDh(caIC, pkIC, domainParams.ec)
	slog.Debug("doCamEcdh", "KA", KA.String())

	// Verify that PKMAP,IC = KA(CAIC, PKIC, DIC).
	if !KA.Equal(*pubMapIC) {
		return fmt.Errorf("[doCamEcdh] PACE CAM verification failed (Bad KA.X/Y) KA:%s, pubMapIC:%s", KA.String(), pubMapIC.String())
	}

	// record that Chip Auth has been performed using PACE-CAM
	(*pace.document).ChipAuthStatus = document.CHIP_AUTH_STATUS_PACE_CAM

	return nil
}

func getKeyForPassword(paceConfig *PaceConfig, pass *password.Password) []byte {
	return cryptoutils.KDF(pass.GetKey(), cryptoutils.KDF_COUNTER_PACE, paceConfig.cipher, paceConfig.keyLengthBits)
}

func (pace *Pace) getNonce(paceConfig *PaceConfig, kKdf []byte) []byte {
	var nonceE []byte
	{
		reqData := []byte{0x7C, 0x00}
		rApduBytes, err := (*pace.nfcSession).GeneralAuthenticate(true, reqData)
		if err != nil {
			// TODO -this is firing for NZ.. maxRead=65536... RAPDU=6982
			//			- maybe we can include this as a catch.. and try to decrease max-read
			//			** needs to be handled somewhere common like doAPDU
			panic(fmt.Sprintf("[getNonce] GeneralAuthenticate error: %s", err))
		}

		nonceE = decodeDynAuthData(0x80, rApduBytes)
	}

	// decrypt the nonce (s)
	return paceConfig.decryptNonce(kKdf, nonceE)
}

// loads the Card Security file and stores it within the Document
func (pace *Pace) loadCardSecurityFile() error {
	const MRTDFileIdCardSecurity = uint16(0x011D)

	fileBytes, err := (*pace.nfcSession).ReadFile(MRTDFileIdCardSecurity)
	if err != nil {
		return fmt.Errorf("[loadCardSecurityFile] ReadFile error: %w", err)
	}

	(*pace.document).Mf.CardSecurity, err = document.NewCardSecurity(fileBytes)
	if err != nil {
		return fmt.Errorf("[loadCardSecurityFile] NewCardSecurity error: %w", err)
	}

	return nil
}

func (pace *Pace) doGenericMappingGmCam(paceConfig *PaceConfig, domainParams *PACEDomainParams, s []byte) (err error) {
	switch domainParams.isECDH {
	case true: // ECDH
		// map the nonce
		var mappedG, pubMapIC *cryptoutils.EcPoint
		mappedG, pubMapIC, err = pace.mapNonceGmEcDh(domainParams, s)
		if err != nil {
			return fmt.Errorf("[doGenericMappingGmCam] mapNonceGmEcDh error: %w", err)
		}

		// Perform Key Agreement
		var sharedSecret []byte
		var kaTermKeypair *cryptoutils.EcKeypair
		var kaChipPub *cryptoutils.EcPoint

		sharedSecret, kaTermKeypair, kaChipPub, err = pace.keyAgreementGmEcDh(domainParams, mappedG)
		if err != nil {
			return fmt.Errorf("[doGenericMappingGmCam] keyAgreementGmEcDh error: %w", err)
		}

		var ecadIC []byte
		ecadIC, err = pace.mutualAuthGmEcDh(paceConfig, domainParams, sharedSecret, kaTermKeypair.Pub, kaChipPub)
		if err != nil {
			return fmt.Errorf("[doGenericMappingGmCam] mutualAuthGmEcDh error: %w", err)
		}

		// Perform Chip Authentication - CAM (if applicable)
		if paceConfig.mapping == CAM {
			// load Card Security file (if required)
			if (*pace.document).Mf.CardSecurity == nil {
				if err = pace.loadCardSecurityFile(); err != nil {
					return fmt.Errorf("[doGenericMappingGmCam] loadCardSecurityFile error: %w", err)
				}
			}

			if err = pace.doCamEcdh(paceConfig, domainParams, pubMapIC, ecadIC); err != nil {
				return fmt.Errorf("[doGenericMappingGmCam] doCamEcdh error: %w", err)
			}
		}
	case false: // DH
		return fmt.Errorf("[doGenericMappingGmCam] PACE GM (DH) NOT IMPLEMENTED")
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

	paceConfig, domainParams, err = selectPaceConfig((*pace.document).Mf.CardAccess)
	if err != nil {
		return fmt.Errorf("[DoPACE] selectPaceConfig error: %w", err)
	}

	slog.Debug("DoPace", "selected paceConfig", paceConfig.String())

	var kKdf []byte = getKeyForPassword(paceConfig, pace.password)

	// init PACE (via 'MSE:Set AT' command)
	if err = pace.doApduMseSetAT(paceConfig, domainParams); err != nil {
		return fmt.Errorf("[DoPACE] doApduMsgSetAT error: %w", err)
	}

	// get nonce
	var s []byte = pace.getNonce(paceConfig, kKdf)

	// process based on the mapping type (GM/IM/CAM) and the key type (ECDH/DH)
	switch paceConfig.mapping {
	case GM, CAM:
		if err = pace.doGenericMappingGmCam(paceConfig, domainParams, s); err != nil {
			return fmt.Errorf("[DoPACE] doGenericMappingGmCam error: %w", err)
		}
	case IM:
		return fmt.Errorf("[DoPACE] PACE-IM NOT IMPLEMENTED")
	}

	slog.Debug("DoPACE - Completed", "SM", (*pace.nfcSession).SM.String())

	return nil
}
