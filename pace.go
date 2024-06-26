package gmrtd

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
	"crypto"
	"crypto/cipher"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"log"
	"log/slog"
	"math/big"

	"github.com/aead/cmac"
	"github.com/ebfe/brainpool"
)

type Pace struct {
	keyGeneratorEc KeyGeneratorEcFn
}

func NewPace() *Pace {
	var pace Pace
	pace.keyGeneratorEc = KeyGeneratorEc
	return &pace
}

type PACEMapping int

const (
	GM PACEMapping = iota
	IM
	CAM
)

type PACESeccureMessaging int

// TODO - is this even used in the code anywhere?... MAC code seems to just infer from cipher-alg... should allow this to be passed in?
const (
	CBC_CBC PACESeccureMessaging = iota
	CBC_CMAC
)

type PACEAuthToken int

const (
	CBC PACEAuthToken = iota
	CMAC
)

type PaceConfig struct {
	oid             asn1.ObjectIdentifier
	mapping         PACEMapping
	cipher          BlockCipherAlg
	keyLengthBits   int
	secureMessaging PACESeccureMessaging
	authToken       PACEAuthToken
	weighting       int
}

func (cfg *PaceConfig) String() string {
	return fmt.Sprintf("(oid:%s, mapping:%d, cipher:%d, keyLenBits:%d, secureMessaging:%d, authToken:%d, weighting:%d)",
		cfg.oid.String(), cfg.mapping, cfg.cipher, cfg.keyLengthBits, cfg.secureMessaging, cfg.authToken, cfg.weighting)
}

//OID								Mapping				Cipher	Keylength	Secure Messaging	Auth. Token
//
//id-PACE-DH-GM-3DES-CBC-CBC 		Generic 			3DES 	112 		CBC / CBC 			CBC
//id-PACE-DH-GM-AES-CBC-CMAC-128 	Generic 			AES 	128 		CBC / CMAC 			CMAC
//id-PACE-DH-GM-AES-CBC-CMAC-192 	Generic 			AES 	192 		CBC / CMAC 			CMAC
//id-PACE-DH-GM-AES-CBC-CMAC-256 	Generic 			AES 	256 		CBC / CMAC 			CMAC
//id-PACE-ECDH-GM-3DES-CBC-CBC 		Generic 			3DES 	112 		CBC / CBC 			CBC
//id-PACE-ECDH-GM-AES-CBC-CMAC-128 	Generic 			AES 	128 		CBC / CMAC 			CMAC
//id-PACE-ECDH-GM-AES-CBC-CMAC-192 	Generic 			AES 	192 		CBC / CMAC 			CMAC
//id-PACE-ECDH-GM-AES-CBC-CMAC-256 	Generic 			AES 	256 		CBC / CMAC 			CMAC
//id-PACE-DH-IM-3DES-CBC-CBC 		Integrated 			3DES 	112			CBC / CBC 			CBC
//id-PACE-DH-IM-AES-CBC-CMAC-128 	Integrated 			AES 	128 		CBC / CMAC 			CMAC
//id-PACE-DH-IM-AES-CBC-CMAC-192 	Integrated 			AES 	192 		CBC / CMAC 			CMAC
//id-PACE-DH-IM-AES-CBC-CMAC-256 	Integrated 			AES 	256 		CBC / CMAC 			CMAC
//id-PACE-ECDH-IM-3DES-CBC-CBC 		Integrated 			3DES 	112 		CBC / CBC 			CBC
//id-PACE-ECDH-IM-AES-CBC-CMAC-128 	Integrated 			AES 	128 		CBC / CMAC 			CMAC
//id-PACE-ECDH-IM-AES-CBC-CMAC-192 	Integrated 			AES 	192 		CBC / CMAC 			CMAC
//id-PACE-ECDH-IM-AES-CBC-CMAC-256 	Integrated 			AES 	256 		CBC / CMAC 			CMAC
//id-PACE-ECDH-CAM-AES-CBC-CMAC-128 Chip Authentication AES 	128 		CBC / CMAC 			CMAC
//id-PACE-ECDH-CAM-AES-CBC-CMAC-192 Chip Authentication AES 	192 		CBC / CMAC 			CMAC
//id-PACE-ECDH-CAM-AES-CBC-CMAC-256 Chip Authentication AES 	256 		CBC / CMAC 			CMAC

// TODO - TDES and AES always have same secureMessaging/AuthToken

var paceConfig = map[string]PaceConfig{

	oidPaceDhGm3DesCbcCbc.String():    {oidPaceDhGm3DesCbcCbc, GM, TDES, 112, CBC_CBC, CBC, 200},
	oidPaceDhGmAesCbcCmac128.String(): {oidPaceDhGmAesCbcCmac128, GM, AES, 128, CBC_CMAC, CMAC, 201},
	oidPaceDhGmAesCbcCmac192.String(): {oidPaceDhGmAesCbcCmac192, GM, AES, 192, CBC_CMAC, CMAC, 202},
	oidPaceDhGmAesCbcCmac256.String(): {oidPaceDhGmAesCbcCmac256, GM, AES, 256, CBC_CMAC, CMAC, 203},

	oidPaceEcdhGm3DesCbcCbc.String():    {oidPaceEcdhGm3DesCbcCbc, GM, TDES, 112, CBC_CBC, CBC, 250},
	oidPaceEcdhGmAesCbcCmac128.String(): {oidPaceEcdhGmAesCbcCmac128, GM, AES, 128, CBC_CMAC, CMAC, 251},
	oidPaceEcdhGmAesCbcCmac192.String(): {oidPaceEcdhGmAesCbcCmac192, GM, AES, 192, CBC_CMAC, CMAC, 252},
	oidPaceEcdhGmAesCbcCmac256.String(): {oidPaceEcdhGmAesCbcCmac256, GM, AES, 256, CBC_CMAC, CMAC, 253},

	oidPaceDhIm3DesCbcCbc.String():    {oidPaceDhIm3DesCbcCbc, IM, TDES, 112, CBC_CBC, CBC, 100},
	oidPaceDhImAesCbcCmac128.String(): {oidPaceDhImAesCbcCmac128, IM, AES, 128, CBC_CMAC, CMAC, 101},
	oidPaceDhImAesCbcCmac192.String(): {oidPaceDhImAesCbcCmac192, IM, AES, 192, CBC_CMAC, CMAC, 102},
	oidPaceDhImAesCbcCmac256.String(): {oidPaceDhImAesCbcCmac256, IM, AES, 256, CBC_CMAC, CMAC, 103},

	oidPaceEcdhIm3DesCbcCbc.String():    {oidPaceEcdhIm3DesCbcCbc, IM, TDES, 112, CBC_CBC, CBC, 150},
	oidPaceEcdhImAesCbcCmac128.String(): {oidPaceEcdhImAesCbcCmac128, IM, AES, 128, CBC_CMAC, CMAC, 151},
	oidPaceEcdhImAesCbcCmac192.String(): {oidPaceEcdhImAesCbcCmac192, IM, AES, 192, CBC_CMAC, CMAC, 152},
	oidPaceEcdhImAesCbcCmac256.String(): {oidPaceEcdhImAesCbcCmac256, IM, AES, 256, CBC_CMAC, CMAC, 153},

	oidPaceEcdhCamAesCbcCmac128.String(): {oidPaceEcdhCamAesCbcCmac128, CAM, AES, 128, CBC_CMAC, CMAC, 300},
	oidPaceEcdhCamAesCbcCmac192.String(): {oidPaceEcdhCamAesCbcCmac192, CAM, AES, 192, CBC_CMAC, CMAC, 301},
	oidPaceEcdhCamAesCbcCmac256.String(): {oidPaceEcdhCamAesCbcCmac256, CAM, AES, 256, CBC_CMAC, CMAC, 302},
}

type PACEDomainParams struct {
	id     int
	isECDH bool
	ec     elliptic.Curve
}

func paceConfigGetByOID(oid asn1.ObjectIdentifier) *PaceConfig {
	out, ok := paceConfig[oid.String()]

	if !ok {
		log.Panicf("paceConfigGetByOID error - OID not found (oid: %s)", oid)
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
		log.Panicf("PACE Standard Domain Parameter (paramId:%1d) NOT IMPLEMENTED", paramId)
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
		log.Panicf("PACE Standard Domain Parameter (paramId:%1d) NOT supported", paramId)
	}

	return ret
}

func (paceConfig *PaceConfig) decryptNonce(key []byte, encryptedNonce []byte) []byte {
	var err error
	var bcipher cipher.Block

	if bcipher, err = GetCipherForKey(paceConfig.cipher, key); err != nil {
		log.Panicf("Unexpected error: %s", err)
	}

	iv := make([]byte, bcipher.BlockSize()) // 0'd IV

	return CryptCBC(bcipher, iv, encryptedNonce, false)
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
	slog.Debug("computeAuthToken", "key", BytesToHex(key), "data", BytesToHex(data))

	switch paceConfig.authToken {
	case CBC:
		// CBC-mode with MAC length of 8 bytes
		// 3DES [FIPS 46-3] SHALL be used in Retail-mode according to [ISO/IEC 9797-1] MAC algorithm 3 / padding method 2 with block cipher DES and IV=0.

		if paceConfig.cipher != TDES {
			log.Panicf("CBC Authentication Token is only supported for 3DES (ActCipherAlg:%d)", int(paceConfig.cipher))
		}

		var err error
		var authToken []byte

		authToken, err = ISO9797RetailMacDes(key, ISO9797Method2Pad(data, DES_BLOCK_SIZE_BYTES))
		if err != nil {
			log.Panicf("Unable to generate Auth-Token (CBC): %s", err.Error())
		}

		slog.Debug("computeAuthToken", "authToken(CBC)", BytesToHex(authToken))
		return authToken
	case CMAC:
		// CMAC-mode with MAC length of 8 bytes
		// AES [FIPS 197] SHALL be used in CMAC-mode [SP 800-38B] with a MAC length of 8 bytes.

		if paceConfig.cipher != AES {
			log.Panicf("CMAC Authentication Token is only supported for AES (ActCipherAlg:%d)", int(paceConfig.cipher))
		}

		var err error
		var cipher cipher.Block

		cipher, err = GetCipherForKey(paceConfig.cipher, key)
		if err != nil {
			log.Panicf("Unable to get cipher (%s)", err)
		}

		authToken, err := cmac.Sum(data, cipher, 8)
		if err != nil {
			log.Panicf("Unable to generate Auth-Token (CMAC): %s", err.Error())
		}

		slog.Debug("computeAuthToken", "authToken(CMAC)", BytesToHex(authToken))
		return authToken
	}

	log.Panicf("Unsupported auth-token alg (%x)", paceConfig.authToken)

	return nil
}

// s: nonce (from chip)
// Hxy: shared secret (derived earlier from ECDH)
// ec: elliptic curve (domain parameters)
func doGenericMappingEC(s []byte, H *EC_POINT, ec elliptic.Curve) *EC_POINT {
	var sGx, sGy *big.Int

	sGx, sGy = ec.ScalarBaseMult(s)

	var out EC_POINT

	out.x, out.y = ec.Add(sGx, sGy, H.x, H.y)

	return &out
}

// TODO - also used by ChipAuth
func encode_7C_XX(innerTag byte, data []byte) []byte {
	node := NewTlvConstructedNode(0x7C)
	node.AddChild(NewTlvSimpleNode(TlvTag(innerTag), data))
	return node.Encode()
}

func decode_7C_XX(innerTag byte, data []byte) []byte {
	return TlvDecode(data).GetNode(0x7C).GetNode(TlvTag(innerTag)).GetValue()
}

func build_7F49(paceOid []byte, tag86data []byte) []byte {
	// 7F49
	//		06 - OID
	//		86 - Uncompressed EC point (x/y)

	node := NewTlvConstructedNode(0x7F49)
	node.AddChild(NewTlvSimpleNode(0x06, paceOid))
	node.AddChild(NewTlvSimpleNode(0x86, tag86data))

	return node.Encode()
}

// TODO - should we make this (and others) a Pace method?
func doAPDU_MSESetAT(nfc *NfcSession, paceConfig *PaceConfig, passwordType PasswordType) (err error) {
	slog.Debug("doAPDU_MSESetAT")

	// manually convert value to reduce reliance on iota values!
	var passwordTypeValue byte
	switch passwordType {
	case PASSWORD_TYPE_MRZi:
		passwordTypeValue = 1
	case PASSWORD_TYPE_CAN:
		passwordTypeValue = 2
	default:
		return fmt.Errorf("unsupported PACE Password-Type (%x)", passwordType)
	}

	paceOidBytes := oidBytes(paceConfig.oid)

	nodes := NewTlvNodes()
	nodes.AddNode(NewTlvSimpleNode(0x80, paceOidBytes))
	nodes.AddNode(NewTlvSimpleNode(0x83, []byte{passwordTypeValue}))

	// MSE:Set AT (0xC1A4: Set Authentication Template for mutual authentication)
	err = nfc.MseSetAT(0xC1, 0xA4, nodes.Encode())
	if err != nil {
		return err
	}

	return nil
}

// mapNonce(EC)
//   - creates keypair
//   - exchanges with chip
//   - generates shared secret
//   - do generic mapping (and return G)
func (pace *Pace) mapNonce_GM_ECDH(nfc *NfcSession, domainParams *PACEDomainParams, s []byte) (mapped_g *EC_POINT, pubMapIC *EC_POINT) {
	slog.Debug("mapNonce_GM_ECDH")

	// generate terminal key (private/public)
	var termPri []byte
	var termPub *EC_POINT
	termPri, termPub = pace.keyGeneratorEc(domainParams.ec)

	// do public-key exchange to get chip pub-key
	{
		reqData := encode_7C_XX(0x81, encodeX962EcPoint(domainParams.ec, termPub))

		rApdu := nfc.GeneralAuthenticate(true, reqData)
		if !rApdu.IsSuccess() {
			log.Panicf("Error mapping the nonce - GM-EC (Status:%x)", rApdu.Status)
		}

		pubMapIC = decodeX962EcPoint(domainParams.ec, decode_7C_XX(0x82, rApdu.Data))
		slog.Debug("mapNonce_GM_ECDH", "pubMapIC", pubMapIC.String())
	}

	//
	// Shared Secret H
	//
	var termShared *EC_POINT = doEcDh(termPri, pubMapIC, domainParams.ec)
	slog.Debug("mapNonce_GM_ECDH", "termShared", termShared.String())

	//
	// Mapped G
	//
	mapped_g = doGenericMappingEC(s, termShared, domainParams.ec)

	return mapped_g, pubMapIC
}

func (pace *Pace) keyAgreement_GM_ECDH(nfc *NfcSession, domainParams *PACEDomainParams, G *EC_POINT) (sharedSecret []byte, termPub *EC_POINT, chipPub *EC_POINT) {
	slog.Debug("keyAgreement_GM_ECDH")

	var termPri []byte
	{
		// reader and chip generate/exchange another set of public-keys
		//			- needs to be generated using mapped-g.x/y
		//			- new keys for terminal
		//			- exchange to get chip keys

		slog.Debug("keyAgreement_GM_ECDH", "Gx", BytesToHex(domainParams.ec.Params().Gx.Bytes()), "Gy", BytesToHex(domainParams.ec.Params().Gy.Bytes()))

		// generate key based on domain-params
		// NB ignore public-key as we'll generate later using the mapped generator (Gx/y)
		termPri, _ = pace.keyGeneratorEc(domainParams.ec)

		// generate the public-key, using the mapped generator (Gxy)
		termPub = new(EC_POINT)
		termPub.x, termPub.y = domainParams.ec.ScalarMult(G.x, G.y, termPri)

		slog.Debug("keyAgreement_GM_ECDH", "termPri", BytesToHex(termPri), "termPub", termPub.String())

		// exchange terminal public-key with chip and get chip's public-key
		{
			reqData := encode_7C_XX(0x83, encodeX962EcPoint(domainParams.ec, termPub))

			rApdu := nfc.GeneralAuthenticate(true, reqData)
			if !rApdu.IsSuccess() {
				log.Panicf("Error performing key agreement - GM-EC (Status:%x)", rApdu.Status)
			}

			chipPub = decodeX962EcPoint(domainParams.ec, decode_7C_XX(0x84, rApdu.Data))
		}
	}

	// verify the terminal and chip public-keys are not the same
	// 9303p11 4.4.1 d) During Diffie-Hellman key agreement, the IC and the inspection system SHOULD check that the two public keys PKDH,IC and PKDH,IFD differ.
	if termPub.Equal(*chipPub) {
		log.Panicf("terminal and chip public-keys must not be the same (Term:%s) (Chip:%s)", termPub.String(), chipPub.String())
	}

	{
		var term_shared *EC_POINT = doEcDh(termPri, chipPub, domainParams.ec)

		// NB secret is just based on 'x'
		sharedSecret = term_shared.x.Bytes()

		slog.Debug("keyAgreement_GM_ECDH", "shared-secret", BytesToHex(sharedSecret))
	}

	return sharedSecret, termPub, chipPub
}

// performs mutual authentication and sets up secure messaging
// ecadIC: only populated for CAM
func (pace *Pace) mutualAuth_GM_ECDH(nfc *NfcSession, paceConfig *PaceConfig, domainParams *PACEDomainParams, sharedSecret []byte, termPub *EC_POINT, chipPub *EC_POINT) (ecadIC []byte) {
	slog.Debug("mutualAuth_GM_ECDH")

	// derive KSenc / KSmac
	var ksEnc, ksMac []byte
	{
		ksEnc = KDF(sharedSecret, KDF_COUNTER_KSENC, paceConfig.cipher, paceConfig.keyLengthBits)
		ksMac = KDF(sharedSecret, KDF_COUNTER_KSMAC, paceConfig.cipher, paceConfig.keyLengthBits)

		slog.Debug("mutualAuth_GM_ECDH", "ksEnc", BytesToHex(ksEnc), "ksMac", BytesToHex(ksMac))
	}

	// generate auth tokens
	var tIfd, tIc []byte
	{
		oidBytes := oidBytes(paceConfig.oid)

		tIfdData := build_7F49(oidBytes, encodeX962EcPoint(domainParams.ec, chipPub))
		tIcData := build_7F49(oidBytes, encodeX962EcPoint(domainParams.ec, termPub))

		// generate auth tokens
		tIfd = paceConfig.computeAuthToken(ksMac, tIfdData)
		tIc = paceConfig.computeAuthToken(ksMac, tIcData)
	}

	// exchange/verify auth tokens (tifd/tic) with passport
	{
		reqData := encode_7C_XX(0x85, tIfd)

		rApdu := nfc.GeneralAuthenticate(false, reqData)
		if !rApdu.IsSuccess() {
			log.Panicf("Error exchanging auth tokens (Status:%x)", rApdu.Status)
		}

		t_ic_rsp := decode_7C_XX(0x86, rApdu.Data)

		// verify that chip responded with the expected 't_ic' value
		if !bytes.Equal(t_ic_rsp, tIc) {
			log.Panicf("Incorrect TIC returned by chip\n[Exp] %x\n[Act] %x", tIc, t_ic_rsp)
		}

		// get Encrypted Chip Authentication Data' (tag:8A) if CAM
		// Encrypted Chip Authentication Data (cf. Section 4.4.3.5) MUST be present if Chip Authentication Mapping is used and MUST NOT be present otherwise.
		if paceConfig.mapping == CAM {
			ecadIC = decode_7C_XX(0x8A, rApdu.Data)
			if len(ecadIC) < 1 {
				log.Panicf("Encrypted Chip Authentication Data (Tag:8A) is mandatory for PACE CAM")
			}
		}
	}

	// setup secure messaging
	{
		var err error
		if nfc.sm, err = NewSecureMessaging(paceConfig.cipher, ksEnc, ksMac); err != nil {
			log.Panicf("Error setting up Secure Messaging: %s", err)
		}
	}

	return ecadIC
}

func getIcPubKeyECForCAM(domainParams *PACEDomainParams, cardSecurity *CardSecurity) *EC_POINT {
	slog.Debug("getIcPubKeyECForCAM")

	var caPubKeyInfos []ChipAuthenticationPublicKeyInfo = cardSecurity.SecurityInfos.ChipAuthPubKeyInfos

	if !domainParams.isECDH {
		log.Panicf("Cannot get EC public key for !EC crypto")
	}

	for i := range caPubKeyInfos {
		// TODO - shouldn't we also check that the Alg.Protocol is as expected (e.g. == standardizedDomainParameters)
		//			- code is here and elsewhere also
		//			- would be good to have a helper that gets the INTfor us
		if bytesToInt(caPubKeyInfos[i].ChipAuthenticationPublicKey.Algorithm.Parameters.Bytes) == domainParams.id {
			var tmpKey []byte = caPubKeyInfos[i].ChipAuthenticationPublicKey.SubjectPublicKey.Bytes
			return decodeX962EcPoint(domainParams.ec, tmpKey)
		}

	}

	log.Panicf("Unable to get Public-Key for CAM")

	return nil
}

// pubMapIC: IC Public Key from earlier mapping operation
// ecadIC: encrypted chip authentication data (tag:8A) from 'mutual auth' response
func (pace *Pace) doCamEcdh(nfc *NfcSession, paceConfig *PaceConfig, domainParams *PACEDomainParams, pubMapIC *EC_POINT, ecadIC []byte, doc *Document) {
	if paceConfig.mapping != CAM {
		log.Panicf("Unexpected mapping during CAM processing (Mapping:%d)", paceConfig.mapping)
	}
	if len(ecadIC) < 1 {
		log.Panicf("ECAD missing")
	}

	slog.Debug("doCamEcdh", "ECAD-IC", BytesToHex(ecadIC))

	// ICAO9303 p11... 4.4.3.3.3 Chip Authentication Mapping

	blockCipher, err := GetCipherForKey(paceConfig.cipher, nfc.sm.ksEnc)
	if err != nil {
		log.Panicf("Unexpected error: %s", err)
	}

	// IV = K(KSenc,-1)
	var iv []byte = make([]byte, blockCipher.BlockSize())
	{
		data := bytes.Repeat([]byte{0xff}, blockCipher.BlockSize())
		blockCipher.Encrypt(iv, data)
	}

	// decrypt the data we got earlier...
	var CA_IC []byte
	{
		// TODO - variable names? (and ecad)
		CA_IC = ISO9797Method2Unpad(CryptCBC(blockCipher, iv, ecadIC, false))
		slog.Debug("doCamEcdh", "CA-IC", BytesToHex(CA_IC))
	}

	// 4.4.3.5.2 Verification by the terminal
	// The terminal SHALL decrypt AIC to recover CAIC and verify PKMap,IC = KA(CAIC, PKIC, DIC), where PKIC is the static public
	// key of the eMRTD chip.

	// t_ic_dcad --> CAic

	{
		// NB we assume that CAM needs to use the same domain-params as used earlier, so we scan card-security file
		//    to find a key that matches the param-id

		// get IC PubKey (EC) for paramId
		var PK_IC *EC_POINT = getIcPubKeyECForCAM(domainParams, doc.CardSecurity)

		var KA *EC_POINT = doEcDh(CA_IC, PK_IC, domainParams.ec)
		slog.Debug("doCamEcdh", "KA", KA.String())

		//
		// Verify that PKMAP,IC = KA(CAIC, PKIC, DIC).
		//
		if !KA.Equal(*pubMapIC) {
			log.Panicf("PACE CAM verification failed (Bad KA.X/Y) KA:%s, pubMapIC:%s", KA.String(), pubMapIC.String())
		}

		// record that Chip Auth has been performed using PACE-CAM
		doc.ChipAuthStatus = CHIP_AUTH_STATUS_PACE_CAM
	}
}

func getKeyForPassword(paceConfig *PaceConfig, password *Password) []byte {
	// generate K
	var k []byte
	switch password.passwordType {
	case PASSWORD_TYPE_MRZi:
		// k = SHA1(mrzi)
		k = CryptoHash(crypto.SHA1, []byte(password.password))
	case PASSWORD_TYPE_CAN:
		// k = CAN
		// NB spec claims that CAN is ISO 8859-1 encoded (9303p11 s9.7.3 PACE)
		//    - we're ignoring this as we don't expect extended characters
		k = []byte(password.password)
	default:
		log.Panicf("Unsupported password-type (type:%d)", password.passwordType)
	}

	return KDF(k, KDF_COUNTER_PACE, paceConfig.cipher, paceConfig.keyLengthBits)
}

func getNonce(nfc *NfcSession, paceConfig *PaceConfig, kKdf []byte) []byte {
	var nonceE []byte
	{
		reqData := []byte{0x7C, 0x00}
		rApdu := nfc.GeneralAuthenticate(true, reqData)
		if !rApdu.IsSuccess() {
			log.Panicf("getNonce error (Status:%x)", rApdu.Status)
		}

		nonceE = decode_7C_XX(0x80, rApdu.Data)
	}

	// decrypt the nonce (s)
	return paceConfig.decryptNonce(kKdf, nonceE)
}

// selects the preferred pace-config based on the options advertised in the card-access file
func selectPaceConfig(cardAccess *CardAccess) (paceConfig *PaceConfig, domainParams *PACEDomainParams) {
	slog.Debug("selectPaceConfig")

	var paceInfos []PaceInfo = cardAccess.SecurityInfos.PaceInfos

	// evaluate all entries and select the preferred, based on the associated weighting
	var selPaceInfo *PaceInfo
	{
		for i := range paceInfos {
			slog.Debug("selectPaceConfig", "paceInfo", paceInfos[i])

			// TODO - this should really be checked during decode
			if paceInfos[i].Version != 2 {
				log.Panicf("PaceInfo version must be 2 (Version:%d)", paceInfos[i].Version)
			}

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

	// TODO - what if this is not set? technically it's optional... should we try to infer.. can do nil check for presence
	domainParams = getStandardisedDomainParams(int(selPaceInfo.ParameterId.Int64()))

	return paceConfig, domainParams
}

func (pace *Pace) doPACE_GM_CAM(nfc *NfcSession, paceConfig *PaceConfig, domainParams *PACEDomainParams, s []byte, doc *Document) (err error) {
	switch domainParams.isECDH {
	case true: // ECDH
		// map the nonce
		var mappedG, pubMapIC *EC_POINT
		mappedG, pubMapIC = pace.mapNonce_GM_ECDH(nfc, domainParams, s)

		// Perform Key Agreement
		var sharedSecret []byte
		var kaTermPub, kaChipPub *EC_POINT
		sharedSecret, kaTermPub, kaChipPub = pace.keyAgreement_GM_ECDH(nfc, domainParams, mappedG)

		var ecadIC []byte
		ecadIC = pace.mutualAuth_GM_ECDH(nfc, paceConfig, domainParams, sharedSecret, kaTermPub, kaChipPub)

		// Perform Chip Authentication (if applicable)
		if paceConfig.mapping == CAM {
			slog.Debug("doPace - CAM - reading CardSecurity")
			// TODO - could skip if we already have CardSecurity? (although we shouldn't)
			if doc.CardSecurity, err = NewCardSecurity(nfc.ReadFile(MRTDFileIdCardSecurity)); err != nil {
				return err
			}
			if doc.CardSecurity == nil {
				return fmt.Errorf("cannot proceed with PACE-CAM without CardSecurity file")
			}
			pace.doCamEcdh(nfc, paceConfig, domainParams, pubMapIC, ecadIC, doc)
		}
	case false: // DH
		return fmt.Errorf("PACE GM (DH) NOT IMPLEMENTED")
	}

	return nil
}

func (pace *Pace) doPACE(nfc *NfcSession, password *Password, doc *Document) (err error) {
	slog.Debug("doPACE", "password-type", password.passwordType, "password", password.password)

	// PACE requires card-access
	if doc.CardAccess == nil {
		slog.Debug("doPACE - SKIPPING as no CardAccess file is present")
		return nil
	}

	var paceConfig *PaceConfig
	var domainParams *PACEDomainParams

	paceConfig, domainParams = selectPaceConfig(doc.CardAccess)

	slog.Debug("doPace", "selected paceConfig", paceConfig.String())

	var kKdf []byte = getKeyForPassword(paceConfig, password)

	// init PACE (via 'MSE:Set AT' command)
	// TODO - aren't there some cases where we need to specified the domain params? (i.e. multiple entries)
	if err = doAPDU_MSESetAT(nfc, paceConfig, password.passwordType); err != nil {
		return err
	}

	// get nonce
	var s []byte = getNonce(nfc, paceConfig, kKdf)

	// process based on the mapping type (GM/IM/CAM) and the key type (ECDH/DH)
	switch paceConfig.mapping {
	case GM, CAM:
		err = pace.doPACE_GM_CAM(nfc, paceConfig, domainParams, s, doc)
		if err != nil {
			return err
		}
	case IM:
		return fmt.Errorf("PACE IM NOT IMPLEMENTED")
	}

	slog.Debug("doPACE - Completed", "SM", nfc.sm.String())

	return nil
}
