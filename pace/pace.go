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
)

type Pace struct {
	keyGeneratorEc cryptoutils.KeyGeneratorEcFn
	nfcSession     *iso7816.NfcSession
	document       *document.Document
	password       *password.Password
}

type paceCamEvidence struct {
	nonce      []byte
	termMapPri []byte
	chipMapPub []byte
	termKaPri  []byte
	chipKaPub  []byte
	ecadIC     []byte
}

func NewPace(nfc *iso7816.NfcSession, doc *document.Document, pass *password.Password) *Pace {
	var pace Pace
	pace.keyGeneratorEc = cryptoutils.KeyGeneratorEc
	pace.nfcSession = nfc
	pace.document = doc
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

func paceConfigGetByOID(oid asn1.ObjectIdentifier) (*PaceConfig, error) {
	out, ok := paceConfig[oid.String()]

	if !ok {
		return nil, fmt.Errorf("[paceConfigGetByOID] unknown OID (%s)", oid)
	}

	return &out, nil
}

// selects the preferred pace-config based on the options advertised in the card-access file
func selectPaceConfig(cardAccess *document.CardAccess) (*PaceConfig, *DomainParams, error) {
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

	domainParams, err := standardisedDomainParams(int(selectedPaceInfo.ParameterId.Int64()))
	if err != nil {
		return nil, nil, fmt.Errorf("[selectPaceConfig] standardisedDomainParams error: %w", err)
	}

	return selectedConfig, domainParams, nil
}

func (paceConfig *PaceConfig) decryptNonce(key, encryptedNonce []byte) ([]byte, error) {
	var err error
	var bcipher cipher.Block

	bcipher, err = cryptoutils.CipherForKey(paceConfig.cipher, key)
	if err != nil {
		return nil, fmt.Errorf("[decryptNonce] CipherForKey error: %w", err)
	}

	iv := make([]byte, bcipher.BlockSize()) // 0'd IV

	tmpDecryptedNonce, err := cryptoutils.CryptCBC(bcipher, iv, encryptedNonce, false)
	if err != nil {
		return nil, fmt.Errorf("[decryptNonce] CryptCBC error: %w", err)
	}

	return tmpDecryptedNonce, nil
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
func decodeDynAuthData(tag byte, data []byte) ([]byte, error) {
	nodes, err := tlv.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decodeDynAuthData: TLV decode error: %w", err)
	}

	node7C := nodes.NodeByTag(0x7C)
	if !node7C.IsValidNode() {
		return nil, fmt.Errorf("decodeDynAuthData: missing tag 7C")
	}

	nodeTag := node7C.NodeByTag(tlv.TlvTag(tag))
	if !nodeTag.IsValidNode() {
		return nil, fmt.Errorf("decodeDynAuthData: missing tag %02X within 7C", tag)
	}

	return nodeTag.Value(), nil
}

// encodes a public-key template (7F49) containing the OID and the public-key (86)
// NB caller should ensure that tag86data is encoded correctly for the underlying key type (DH/ECDH)
func encodePubicKeyTemplate7F49(paceOid, tag86data []byte) []byte {
	// 7F49
	//		06 - OID
	//		86 - Uncompressed EC point (x/y)

	node := tlv.NewTlvConstructedNode(0x7F49)
	node.AddChild(tlv.NewTlvSimpleNode(0x06, paceOid))
	node.AddChild(tlv.NewTlvSimpleNode(0x86, tag86data))

	return node.Encode()
}

func (pace *Pace) doApduMseSetAT(paceConfig *PaceConfig, domainParams *DomainParams) (err error) {
	slog.Debug("doApduMseSetAT")

	paceOidBytes := oid.OidBytes(paceConfig.oid)

	var passType byte

	passType, err = pace.password.Type()
	if err != nil {
		return fmt.Errorf("[doApduMseSetAT] password.Type error: %w", err)
	}

	var nodes *tlv.TlvNodes = &tlv.TlvNodes{}
	nodes.AddNode(tlv.NewTlvSimpleNode(0x80, paceOidBytes))
	nodes.AddNode(tlv.NewTlvSimpleNode(0x83, []byte{passType}))
	// this should be CONDITIONAL and only provided where there is ambiguity, but
	// we've seen some passports that always expect this to be provided
	nodes.AddNode(tlv.NewTlvSimpleNode(0x84, []byte{byte(domainParams.id)}))

	// MSE:Set AT (0xC1A4: Set Authentication Template for mutual authentication)
	err = pace.nfcSession.MseSetAT(0xC1, 0xA4, nodes.Encode())
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
func (pace *Pace) mapNonceGmEcDh(domainParams *DomainParams, s []byte) (mapped_g *cryptoutils.EcPoint, pubMapIC *cryptoutils.EcPoint, termMapPri []byte, err error) {
	slog.Debug("mapNonceGmEcDh", "s", utils.BytesToHex(s))

	// generate terminal key (private/public)
	var termKeypair cryptoutils.EcKeypair = pace.keyGeneratorEc(domainParams.ec)

	termMapPri = bytes.Clone(termKeypair.Pri)

	// do public-key exchange to get chip pub-key
	{
		reqData := encodeDynAuthData(0x81, cryptoutils.EncodeX962EcPoint(domainParams.ec, termKeypair.Pub))

		rApduBytes, err := pace.nfcSession.GeneralAuthenticate(true, reqData)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("[mapNonceGmEcDh] GeneralAuthenticate error: %w", err)
		}

		dynAuthBytes, err := decodeDynAuthData(0x82, rApduBytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("[mapNonceGmEcDh] %w", err)
		}
		pubMapIC, err = cryptoutils.DecodeX962EcPoint(domainParams.ec, dynAuthBytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("[mapNonceGmEcDh] %w", err)
		}
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

	return mapped_g, pubMapIC, termMapPri, nil
}

func (pace *Pace) keyAgreementGmEcDh(domainParams *DomainParams, G *cryptoutils.EcPoint) (sharedSecret []byte, termKeypair *cryptoutils.EcKeypair, chipPub *cryptoutils.EcPoint, err error) {
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

		rApduBytes, err := pace.nfcSession.GeneralAuthenticate(true, reqData)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("[keyAgreementGmEcDh] GeneralAuthenticate error: %w", err)
		}

		dynAuthBytes, err := decodeDynAuthData(0x84, rApduBytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("[keyAgreementGmEcDh] %w", err)
		}
		chipPub, err = cryptoutils.DecodeX962EcPoint(domainParams.ec, dynAuthBytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("[keyAgreementGmEcDh] %w", err)
		}
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
func (pace *Pace) mutualAuthGmEcDh(paceConfig *PaceConfig, domainParams *DomainParams, sharedSecret []byte, termPub *cryptoutils.EcPoint, chipPub *cryptoutils.EcPoint) (ecadIC []byte, err error) {
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

		rApduBytes, err := pace.nfcSession.GeneralAuthenticate(false, reqData)
		if err != nil {
			return nil, fmt.Errorf("[mutualAuthGmEcDh] GeneralAuthenticate error: %w", err)
		}

		tIc2, err := decodeDynAuthData(0x86, rApduBytes)
		if err != nil {
			return nil, fmt.Errorf("[mutualAuthGmEcDh] %w", err)
		}

		// verify that chip responded with the expected 'tIC' value
		if !bytes.Equal(tIc2, tIc) {
			return nil, fmt.Errorf("[mutualAuthGmEcDh] Incorrect TIC returned by chip\n[Exp] %x\n[Act] %x", tIc, tIc2)
		}

		// get Encrypted Chip Authentication Data' (tag:8A) if CAM
		// Encrypted Chip Authentication Data (cf. Section 4.4.3.5) MUST be present if Chip Authentication Mapping is used and MUST NOT be present otherwise.
		if paceConfig.mapping == CAM {
			ecadIC, err = decodeDynAuthData(0x8A, rApduBytes)
			if err != nil {
				return nil, fmt.Errorf("[mutualAuthGmEcDh] Encrypted Chip Authentication Data (Tag:8A) is mandatory for PACE CAM: %w", err)
			}
		}
	}

	// setup secure messaging
	{
		slog.Debug("mutualAuthGmEcDh - setting up SM")
		sm, err := iso7816.NewSecureMessaging(paceConfig.cipher, ksEnc, ksMac)
		if err != nil {
			return nil, fmt.Errorf("[mutualAuthGmEcDh] NewSecureMessaging error: %w", err)
		}
		pace.nfcSession.SetSecureMessaging(sm)
		slog.Debug("mutualAuthGmEcDh", "SM", pace.nfcSession.SM().String())
	}

	return ecadIC, nil
}

func icPubKeyECForCAM(domainParams *DomainParams, cardSecurity *document.CardSecurity) (*cryptoutils.EcPoint, error) {
	slog.Debug("icPubKeyECForCAM")

	var caPubKeyInfos []document.ChipAuthenticationPublicKeyInfo = cardSecurity.SecurityInfos.ChipAuthPubKeyInfos

	if !domainParams.isECDH {
		return nil, fmt.Errorf("[icPubKeyECForCAM] Cannot get EC public key for !EC crypto")
	}

	for i := range caPubKeyInfos {
		var subjectPubKeyInfo *cms.SubjectPublicKeyInfo = &caPubKeyInfos[i].ChipAuthenticationPublicKey

		// only evaluate EC keys
		if subjectPubKeyInfo.Algorithm.Algorithm.Equal(oid.OidBsiDeEcKeyType) {
			if utils.BytesToInt(subjectPubKeyInfo.Algorithm.Parameters.Bytes) == domainParams.id {
				var tmpKey []byte = subjectPubKeyInfo.SubjectPublicKey.Bytes
				point, err := cryptoutils.DecodeX962EcPoint(domainParams.ec, tmpKey)
				if err != nil {
					return nil, fmt.Errorf("[icPubKeyECForCAM] %w", err)
				}
				return point, nil
			}
		}
	}

	return nil, fmt.Errorf("[icPubKeyECForCAM] Unable to get Public-Key for CAM")
}

func decryptEcadIC(cipherAlg cryptoutils.BlockCipherAlg, ksEnc, ecadIC []byte) ([]byte, error) {
	blockCipher, err := cryptoutils.CipherForKey(cipherAlg, ksEnc)
	if err != nil {
		return nil, fmt.Errorf("[decryptEcadIC] CipherForKey error: %w", err)
	}

	// IV = E(KSenc, 0xFF...)
	var iv []byte = make([]byte, blockCipher.BlockSize())
	// Note: suppress secure mode and padding scheme warning in sonar
	//		 - this is required for CAM ECDH to generate the IV
	blockCipher.Encrypt(iv, bytes.Repeat([]byte{0xff}, blockCipher.BlockSize())) // NOSONAR

	tmpDecryptedValue, err := cryptoutils.CryptCBC(blockCipher, iv, ecadIC, false)
	if err != nil {
		return nil, fmt.Errorf("[decryptEcadIC] CryptCBC error: %w", err)
	}

	caIC, err := cryptoutils.ISO9797Method2Unpad(tmpDecryptedValue)
	if err != nil {
		return nil, fmt.Errorf("[decryptEcadIC] ISO9797Method2Unpad error: %w", err)
	}

	return caIC, nil
}

// pubMapIC: IC Public Key from earlier mapping operation
// ecadIC: encrypted chip authentication data (tag:8A) from 'mutual auth' response
func (pace *Pace) doCamEcdh(paceConfig *PaceConfig, domainParams *DomainParams, pubMapIC *cryptoutils.EcPoint, ecadIC []byte) (err error) {
	if paceConfig.mapping != CAM {
		return fmt.Errorf("[doCamEcdh] Unexpected mapping during CAM processing (Mapping:%d)", paceConfig.mapping)
	}
	if len(ecadIC) < 1 {
		return fmt.Errorf("[doCamEcdh] ECAD missing")
	}

	slog.Debug("doCamEcdh", "ECAD-IC", utils.BytesToHex(ecadIC))

	// ICAO9303 p11... 4.4.3.3.3 Chip Authentication Mapping

	caIC, err := decryptEcadIC(paceConfig.cipher, pace.nfcSession.SM().KsEnc(), ecadIC)
	if err != nil {
		return fmt.Errorf("[doCamEcdh] %w", err)
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
	pkIC, err = icPubKeyECForCAM(domainParams, pace.document.Mf.CardSecurity)
	if err != nil {
		return fmt.Errorf("[doCamEcdh] icPubKeyECForCAM error: %w", err)
	}

	var KA *cryptoutils.EcPoint = cryptoutils.DoEcDh(caIC, pkIC, domainParams.ec)
	slog.Debug("doCamEcdh", "KA", KA.String())

	// Verify that PKMAP,IC = KA(CAIC, PKIC, DIC).
	if !KA.Equal(*pubMapIC) {
		return fmt.Errorf("[doCamEcdh] PACE CAM verification failed (Bad KA.X/Y) KA:%s, pubMapIC:%s", KA.String(), pubMapIC.String())
	}

	return nil
}

func keyForPassword(paceConfig *PaceConfig, pass *password.Password) ([]byte, error) {
	key, err := pass.Key()
	if err != nil {
		return nil, fmt.Errorf("[keyForPassword] password.Key error: %w", err)
	}

	return cryptoutils.KDF(key, cryptoutils.KDF_COUNTER_PACE, paceConfig.cipher, paceConfig.keyLengthBits), nil
}

func (pace *Pace) getNonce(paceConfig *PaceConfig, kKdf []byte) ([]byte, error) {
	var nonceE []byte
	{
		reqData := []byte{0x7C, 0x00}
		rApduBytes, err := pace.nfcSession.GeneralAuthenticate(true, reqData)
		if err != nil {
			// TODO -this is firing for NZ.. maxRead=65536... RAPDU=6982
			//			- maybe we can include this as a catch.. and try to decrease max-read
			//			** needs to be handled somewhere common like doAPDU
			return nil, fmt.Errorf("[getNonce] GeneralAuthenticate error: %w", err)
		}

		nonceE, err = decodeDynAuthData(0x80, rApduBytes)
		if err != nil {
			return nil, fmt.Errorf("[getNonce] %w", err)
		}
	}

	// decrypt the nonce (s)
	tmpDecryptedNonce, err := paceConfig.decryptNonce(kKdf, nonceE)
	if err != nil {
		return nil, fmt.Errorf("[getNonce] decryptNonce error: %w", err)
	}

	return tmpDecryptedNonce, nil
}

// loads the Card Security file and stores it within the Document
func (pace *Pace) loadCardSecurityFile() error {
	const MRTDFileIdCardSecurity = uint16(0x011D)

	fileBytes, err := pace.nfcSession.ReadFile(MRTDFileIdCardSecurity)
	if err != nil {
		return fmt.Errorf("[loadCardSecurityFile] ReadFile error: %w", err)
	}

	pace.document.Mf.CardSecurity, err = document.NewCardSecurity(fileBytes)
	if err != nil {
		return fmt.Errorf("[loadCardSecurityFile] NewCardSecurity error: %w", err)
	}

	return nil
}

func (pace *Pace) doGenericMappingGmCam(paceConfig *PaceConfig, domainParams *DomainParams, s []byte) (evidence *paceCamEvidence, err error) {
	switch domainParams.isECDH {
	case true: // ECDH
		// map the nonce
		var mappedG, pubMapIC *cryptoutils.EcPoint
		var termMapPri []byte
		mappedG, pubMapIC, termMapPri, err = pace.mapNonceGmEcDh(domainParams, s)
		if err != nil {
			return nil, fmt.Errorf("[doGenericMappingGmCam] mapNonceGmEcDh error: %w", err)
		}

		// Perform Key Agreement
		var sharedSecret []byte
		var kaTermKeypair *cryptoutils.EcKeypair
		var kaChipPub *cryptoutils.EcPoint

		sharedSecret, kaTermKeypair, kaChipPub, err = pace.keyAgreementGmEcDh(domainParams, mappedG)
		if err != nil {
			return nil, fmt.Errorf("[doGenericMappingGmCam] keyAgreementGmEcDh error: %w", err)
		}

		var ecadIC []byte
		ecadIC, err = pace.mutualAuthGmEcDh(paceConfig, domainParams, sharedSecret, kaTermKeypair.Pub, kaChipPub)
		if err != nil {
			return nil, fmt.Errorf("[doGenericMappingGmCam] mutualAuthGmEcDh error: %w", err)
		}

		// Perform Chip Authentication - CAM (if applicable)
		if paceConfig.mapping == CAM {
			// load Card Security file (if required)
			if pace.document.Mf.CardSecurity == nil {
				if err = pace.loadCardSecurityFile(); err != nil {
					return nil, fmt.Errorf("[doGenericMappingGmCam] loadCardSecurityFile error: %w", err)
				}
			}

			if err = pace.doCamEcdh(paceConfig, domainParams, pubMapIC, ecadIC); err != nil {
				return nil, fmt.Errorf("[doGenericMappingGmCam] doCamEcdh error: %w", err)
			}

			// capture evidence for independent re-verification
			evidence = &paceCamEvidence{
				nonce:      bytes.Clone(s),
				termMapPri: termMapPri,
				chipMapPub: cryptoutils.EncodeX962EcPoint(domainParams.ec, pubMapIC),
				termKaPri:  bytes.Clone(kaTermKeypair.Pri),
				chipKaPub:  cryptoutils.EncodeX962EcPoint(domainParams.ec, kaChipPub),
				ecadIC:     bytes.Clone(ecadIC),
			}
		}
	case false: // DH
		return nil, fmt.Errorf("[doGenericMappingGmCam] PACE GM (DH) NOT IMPLEMENTED")
	}

	return evidence, nil
}

func (pace *Pace) DoPACE() (result *document.PaceResult, camResult *document.PaceCamResult, err error) {
	slog.Debug("DoPACE", "password-type", pace.password.PasswordType, "password", pace.password.Password)

	// PACE requires card-access
	if pace.document.Mf.CardAccess == nil {
		slog.Debug("DoPACE - SKIPPING as no CardAccess file is present")
		return nil, nil, nil
	}

	// setup the result (but mark as !success)
	result = &document.PaceResult{Success: false}

	var paceConfig *PaceConfig
	var domainParams *DomainParams

	paceConfig, domainParams, err = selectPaceConfig(pace.document.Mf.CardAccess)
	if err != nil {
		return result, nil, fmt.Errorf("[DoPACE] selectPaceConfig error: %w", err)
	}

	// update result to indicate the selected OID/ParameterId
	result.Oid = paceConfig.oid
	result.ParameterId = domainParams.id

	slog.Debug("DoPace", "selected paceConfig", paceConfig.String())

	var kKdf []byte

	kKdf, err = keyForPassword(paceConfig, pace.password)
	if err != nil {
		return result, nil, fmt.Errorf("[DoPACE] keyForPassword error: %w", err)
	}

	// init PACE (via 'MSE:Set AT' command)
	if err = pace.doApduMseSetAT(paceConfig, domainParams); err != nil {
		return result, nil, fmt.Errorf("[DoPACE] doApduMseSetAT error: %w", err)
	}

	// get nonce
	var s []byte
	s, err = pace.getNonce(paceConfig, kKdf)
	if err != nil {
		return result, nil, fmt.Errorf("[DoPACE] getNonce error: %w", err)
	}

	// process based on the mapping type (GM/IM/CAM) and the key type (ECDH/DH)
	switch paceConfig.mapping {
	case GM, CAM:
		var camEvidence *paceCamEvidence
		camEvidence, err = pace.doGenericMappingGmCam(paceConfig, domainParams, s)
		if err != nil {
			return result, nil, fmt.Errorf("[DoPACE] doGenericMappingGmCam error: %w", err)
		}
		if paceConfig.mapping == CAM && camEvidence != nil {
			camResult = &document.PaceCamResult{
				Success: true,
				Evidence: &document.PaceCamEvidence{
					PaceOid:     paceConfig.oid,
					ParameterId: domainParams.id,
					Nonce:       camEvidence.nonce,
					TermMapPri:  camEvidence.termMapPri,
					ChipMapPub:  camEvidence.chipMapPub,
					TermKaPri:   camEvidence.termKaPri,
					ChipKaPub:   camEvidence.chipKaPub,
					EcadIC:      camEvidence.ecadIC,
				},
			}
		}
	case IM:
		return result, nil, fmt.Errorf("[DoPACE] PACE-IM NOT IMPLEMENTED")
	}

	// update result to indicate success
	result.Success = true

	slog.Debug("DoPACE - Completed", "SM", pace.nfcSession.SM().String())

	return result, camResult, nil
}

// VerifyEvidence independently verifies PACE-CAM evidence without a live NFC session.
// It requires the Document (which supplies the chip's static EC public key from
// CardSecurity) and the evidence captured during the original PACE-CAM session.
//
// Verification replays the PACE key-derivation chain from the captured ephemeral keys:
//  1. Re-derives the mapping shared secret and mapped generator from the nonce and
//     terminal mapping private key.
//  2. Re-derives the key-agreement shared secret and session keys (ksEnc).
//  3. Decrypts the encrypted chip authentication data (EcadIC) using ksEnc to recover
//     caIC.
//  4. Verifies KA(caIC, pkIC, ec) == ChipMapPub, proving the chip held the private key
//     matching the static public key in CardSecurity.
//
// The Nonce and TermMapPri fields are replayed for completeness but cannot be
// independently verified — the security proof rests on the CAM verification (step 4).
//
// A successful result proves the chip held the private key matching the public key in
// CardSecurity during the original session. Callers must also verify the Document via
// Passive Authentication to confirm that CardSecurity is bound to a trusted CSCA chain.
const maxEvidenceFieldLen = 1024

func VerifyEvidence(doc *document.Document, evidence *document.PaceCamEvidence) (*document.PaceCamResult, error) {
	if evidence == nil {
		return nil, fmt.Errorf("[VerifyEvidence] evidence is nil")
	}

	if len(evidence.Nonce) == 0 || len(evidence.TermMapPri) == 0 || len(evidence.ChipMapPub) == 0 ||
		len(evidence.TermKaPri) == 0 || len(evidence.ChipKaPub) == 0 || len(evidence.EcadIC) == 0 {
		return nil, fmt.Errorf("[VerifyEvidence] evidence has empty field(s)")
	}

	if len(evidence.Nonce) > maxEvidenceFieldLen || len(evidence.TermMapPri) > maxEvidenceFieldLen ||
		len(evidence.ChipMapPub) > maxEvidenceFieldLen || len(evidence.TermKaPri) > maxEvidenceFieldLen ||
		len(evidence.ChipKaPub) > maxEvidenceFieldLen || len(evidence.EcadIC) > maxEvidenceFieldLen {
		return nil, fmt.Errorf("[VerifyEvidence] evidence field exceeds maximum length (%d)", maxEvidenceFieldLen)
	}

	if doc.Mf.CardSecurity == nil {
		return nil, fmt.Errorf("[VerifyEvidence] CardSecurity is nil")
	}

	paceConfig, err := paceConfigGetByOID(evidence.PaceOid)
	if err != nil {
		return nil, fmt.Errorf("[VerifyEvidence] paceConfigGetByOID error: %w", err)
	}

	if paceConfig.mapping != CAM {
		return nil, fmt.Errorf("[VerifyEvidence] evidence OID is not PACE-CAM")
	}

	domainParams, err := standardisedDomainParams(evidence.ParameterId)
	if err != nil {
		return nil, fmt.Errorf("[VerifyEvidence] standardisedDomainParams error: %w", err)
	}

	if !domainParams.isECDH {
		return nil, fmt.Errorf("[VerifyEvidence] domain params are not ECDH")
	}

	chipMapPub, err := cryptoutils.DecodeX962EcPoint(domainParams.ec, evidence.ChipMapPub)
	if err != nil {
		return nil, fmt.Errorf("[VerifyEvidence] DecodeX962EcPoint(ChipMapPub) error: %w", err)
	}

	chipKaPub, err := cryptoutils.DecodeX962EcPoint(domainParams.ec, evidence.ChipKaPub)
	if err != nil {
		return nil, fmt.Errorf("[VerifyEvidence] DecodeX962EcPoint(ChipKaPub) error: %w", err)
	}

	// re-derive mapping shared secret and mapped generator
	H := cryptoutils.DoEcDh(evidence.TermMapPri, chipMapPub, domainParams.ec)
	_ = doGenericMappingEC(evidence.Nonce, H, domainParams.ec)

	// re-derive key-agreement shared secret and session keys
	kaShared := cryptoutils.DoEcDh(evidence.TermKaPri, chipKaPub, domainParams.ec)
	sharedSecret := kaShared.X.Bytes()
	ksEnc := cryptoutils.KDF(sharedSecret, cryptoutils.KDF_COUNTER_KSENC, paceConfig.cipher, paceConfig.keyLengthBits)

	// decrypt EcadIC to recover caIC
	caIC, err := decryptEcadIC(paceConfig.cipher, ksEnc, evidence.EcadIC)
	if err != nil {
		return nil, fmt.Errorf("[VerifyEvidence] %w", err)
	}

	// get chip static public key from CardSecurity
	pkIC, err := icPubKeyECForCAM(domainParams, doc.Mf.CardSecurity)
	if err != nil {
		return nil, fmt.Errorf("[VerifyEvidence] icPubKeyECForCAM error: %w", err)
	}

	// verify KA(caIC, pkIC, ec) == chipMapPub
	KA := cryptoutils.DoEcDh(caIC, pkIC, domainParams.ec)
	if !KA.Equal(*chipMapPub) {
		return nil, fmt.Errorf("[VerifyEvidence] PACE CAM verification failed")
	}

	return &document.PaceCamResult{
		Success:  true,
		Evidence: evidence,
	}, nil
}
