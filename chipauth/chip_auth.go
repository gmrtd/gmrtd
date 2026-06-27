// Package chipauth implements the 'Chip Authentication' mechanism for verifying the authenticity of the Contactless IC.
package chipauth

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"math/big"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

type ChipAuth struct {
	keyGeneratorEc cryptoutils.KeyGeneratorEcFn
	nfcSession     **iso7816.NfcSession
	document       **document.Document
}

func NewChipAuth(nfc *iso7816.NfcSession, doc *document.Document) *ChipAuth {
	var chipAuth ChipAuth
	chipAuth.keyGeneratorEc = cryptoutils.KeyGeneratorEc
	chipAuth.nfcSession = &nfc
	chipAuth.document = &doc
	return &chipAuth
}

// ChipAuthParams holds the resolved CA parameters selected from the document.
type ChipAuthParams struct {
	Info        *document.ChipAuthenticationInfo
	AlgInfo     *CaAlgorithmInfo
	PubKeyInfo  *document.ChipAuthenticationPublicKeyInfo
	AlgInferred bool
}

type caEcdhEvidence struct {
	termPri    []byte
	termPubKey []byte
	smRapdu    []byte
	smSsc      []byte
}

func selectChipAuthParams(doc *document.Document) (*ChipAuthParams, error) {
	secInfos := doc.Mf.Lds1.Dg14.SecInfos

	caInfo, caAlgInfo, algInferred, err := resolveCAInfo(secInfos)
	if err != nil {
		return nil, fmt.Errorf("[selectChipAuthParams] resolveCAInfo error: %w", err)
	}

	caPubKeyInfo, err := selectCAPubKeyInfo(caInfo, caAlgInfo, doc)
	if err != nil {
		return nil, fmt.Errorf("[selectChipAuthParams] selectCAPubKeyInfo error: %w", err)
	}

	return &ChipAuthParams{
		Info:        caInfo,
		AlgInfo:     caAlgInfo,
		PubKeyInfo:  caPubKeyInfo,
		AlgInferred: algInferred,
	}, nil
}

func (chipAuth *ChipAuth) DoChipAuth() (result *document.ChipAuthResult, err error) {
	if !caAdvertised(*chipAuth.document) {
		slog.Debug("doChipAuth - skipping CA as not advertised")
		// NB no need to return result or error
		return nil, nil
	}

	// setup the result (but mark as !success)
	result = &document.ChipAuthResult{Success: false}

	if (*chipAuth.nfcSession).SM() != nil {
		slog.Debug("doChipAuth", "SM(pre)", (*chipAuth.nfcSession).SM().String())
	}

	params, err := selectChipAuthParams(*chipAuth.document)
	if err != nil {
		return result, fmt.Errorf("[DoChipAuth] selectChipAuthParams error: %w", err)
	}

	evidence, err := chipAuth.executeCA(params)
	if err != nil {
		return result, fmt.Errorf("[DoChipAuth] executeCA error: %w", err)
	}

	// update result to indicate success
	result.Success = true

	if evidence != nil {
		result.Evidence = &document.ChipAuthEvidence{
			TermPri:    evidence.termPri,
			TermPubKey: evidence.termPubKey,
			SmRapdu:    evidence.smRapdu,
			SmSsc:      evidence.smSsc,
		}
	}

	if (*chipAuth.nfcSession).SM() != nil {
		slog.Debug("doChipAuth", "SM(post)", (*chipAuth.nfcSession).SM().String())
	}

	return result, nil
}

func caAdvertised(doc *document.Document) bool {
	// DG14 must be present
	if doc.Mf.Lds1.Dg14 == nil {
		slog.Debug("caAdvertised - DG14 is not present")
		return false
	}

	// ChipAuthInfos OR ChipAuthPubKeyInfos must be present (i.e. advertising CA)
	if len(doc.Mf.Lds1.Dg14.SecInfos.ChipAuthInfos) < 1 &&
		len(doc.Mf.Lds1.Dg14.SecInfos.ChipAuthPubKeyInfos) < 1 {
		slog.Debug("caAdvertised - ChipAuthInfos/ChipAuthPubKeyInfos not present")
		return false
	}

	return true
}

func resolveCAInfo(secInfos *document.SecurityInfos) (
	caInfo *document.ChipAuthenticationInfo,
	caAlgInfo *CaAlgorithmInfo,
	algInferred bool,
	err error,
) {
	caInfo, caAlgInfo, err = selectCAInfo(secInfos)
	if err != nil {
		return nil, nil, false, fmt.Errorf("[resolveCAInfo] selectCAInfo error: %w", err)
	}

	if caInfo != nil && caAlgInfo != nil {
		return caInfo, caAlgInfo, false, nil
	}

	// try to infer from any available CA key
	caInfo, caAlgInfo, err = inferCAInfoFromKey(secInfos.ChipAuthPubKeyInfos)
	if err != nil {
		return nil, nil, false, fmt.Errorf("[resolveCAInfo] inferCAInfoFromKey error: %w", err)
	}

	if caInfo != nil && caAlgInfo != nil {
		return caInfo, caAlgInfo, true, nil
	}

	return nil, nil, false, fmt.Errorf("[resolveCAInfo] Unable to resolve caInfo/caAlgInfo")
}

func (chipAuth *ChipAuth) executeCA(params *ChipAuthParams) (*caEcdhEvidence, error) {
	// process based on the type of key (DH/ECDH)
	switch {
	case params.PubKeyInfo.Protocol.Equal(oid.OidPkDh):
		// DH
		return nil, fmt.Errorf("[executeCA] DH not currently supported (Raw:%x)", params.PubKeyInfo.Raw)

	case params.PubKeyInfo.Protocol.Equal(oid.OidPkEcdh):
		// ECDH
		evidence, err := chipAuth.doCaEcdh(params)
		if err != nil {
			return nil, fmt.Errorf("[executeCA] doCaEcdh error: %w", err)
		}
		return evidence, nil

	default:
		return nil, fmt.Errorf("[executeCA] unsupported public key type (OID:%s)", params.PubKeyInfo.Protocol.String())
	}
}

// selects the 'preferred' CA entry (if any are present)
// returns: nil (caAuthInfo/caAlgInfo) if none found, otherwise preferred CA entry
func selectCAInfo(secInfos *document.SecurityInfos) (caInfo *document.ChipAuthenticationInfo, caAlgInfo *CaAlgorithmInfo, err error) {
	slog.Debug("selectCAInfo")

	var bestCaInfo *document.ChipAuthenticationInfo
	var bestCaAlgInfo *CaAlgorithmInfo

	for i := range secInfos.ChipAuthInfos {
		var curCaInfo *document.ChipAuthenticationInfo
		var curCaAlgInfo *CaAlgorithmInfo

		curCaInfo = &(secInfos.ChipAuthInfos[i])

		curCaAlgInfo, err = algInfo(curCaInfo.Protocol)
		if err != nil {
			return nil, nil, fmt.Errorf("[selectCAInfo] algInfo error: %w", err)
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
func inferCAInfoFromKey(chipAuthPubKeyInfos []document.ChipAuthenticationPublicKeyInfo) (caInfo *document.ChipAuthenticationInfo, caAlgInfo *CaAlgorithmInfo, err error) {
	slog.Debug("inferCAInfoFromKey")

	/*
	* Some passports (e.g. FR) are missing the ca-info, so we default to 3DES
	 */

	if len(chipAuthPubKeyInfos) > 0 {
		// just go with the 1st key
		var keyInfo *document.ChipAuthenticationPublicKeyInfo = &(chipAuthPubKeyInfos[0])

		caInfo, err = inferCAInfoFromKeyProtocol(keyInfo.Protocol)
		if err != nil {
			return nil, nil, fmt.Errorf("[inferCAInfoFromKey] inferCAInfoFromKeyProtocol error: %w", err)
		}

		caAlgInfo, err = algInfo(caInfo.Protocol)
		if err != nil {
			return nil, nil, fmt.Errorf("[inferCAInfoFromKey] algInfo error: %w", err)
		}
	} else {
		slog.Debug("inferCAInfoFromKey - skip due to lack of ChipAuthPubKeyInfos")
	}

	return caInfo, caAlgInfo, nil
}

// infer the CAInfo from the provided Protocol(OID)
// returns: caInfo or error
func inferCAInfoFromKeyProtocol(protocol asn1.ObjectIdentifier) (caInfo *document.ChipAuthenticationInfo, err error) {
	// process based on the type of key (DH/ECDH)
	if protocol.Equal(oid.OidPkDh) {
		// DH
		caInfo = &document.ChipAuthenticationInfo{Protocol: oid.OidCaDh3DesCbcCbc, Version: 1}
	} else if protocol.Equal(oid.OidPkEcdh) {
		// ECDH
		caInfo = &document.ChipAuthenticationInfo{Protocol: oid.OidCaEcdh3DesCbcCbc, Version: 1}
	} else {
		return nil, fmt.Errorf("[inferCAInfoFromKeyProtocol] unsupported key type (OID:%s)", protocol.String())
	}

	return caInfo, nil
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

	return nil, fmt.Errorf("[selectCAPubKeyInfo] unable to locate public key (oid:%s) (keyId:%s)", caAlgInfo.targetOid.String(), caInfo.KeyId)
}

type CaAlgorithmInfo struct {
	targetOid   asn1.ObjectIdentifier
	cipherAlg   cryptoutils.BlockCipherAlg
	keySizeBits int
	weighting   int
}

// NB weighting: we prioritise ECDH (2xxx) over DH (1xxx), then select based on key-bits
var caAlgInfoLookup = map[string]CaAlgorithmInfo{
	oid.OidCaDh3DesCbcCbc.String():    {oid.OidPkDh, cryptoutils.TDES, 112, 1112},
	oid.OidCaDhAesCbcCmac128.String(): {oid.OidPkDh, cryptoutils.AES, 128, 1128},
	oid.OidCaDhAesCbcCmac192.String(): {oid.OidPkDh, cryptoutils.AES, 192, 1192},
	oid.OidCaDhAesCbcCmac256.String(): {oid.OidPkDh, cryptoutils.AES, 256, 1256},

	oid.OidCaEcdh3DesCbcCbc.String():    {oid.OidPkEcdh, cryptoutils.TDES, 112, 2112},
	oid.OidCaEcdhAesCbcCmac128.String(): {oid.OidPkEcdh, cryptoutils.AES, 128, 2128},
	oid.OidCaEcdhAesCbcCmac192.String(): {oid.OidPkEcdh, cryptoutils.AES, 192, 2192},
	oid.OidCaEcdhAesCbcCmac256.String(): {oid.OidPkEcdh, cryptoutils.AES, 256, 2256},
}

func algInfo(oid asn1.ObjectIdentifier) (*CaAlgorithmInfo, error) {
	out, ok := caAlgInfoLookup[oid.String()]

	if !ok {
		return nil, fmt.Errorf("[algInfo] OID not found (%s)", oid.String())
	}

	return &out, nil
}

func (chipAuth *ChipAuth) doMseSetKAT(curve *elliptic.Curve, termKeypair cryptoutils.EcKeypair, caInfo *document.ChipAuthenticationInfo) error {
	// MSE:Set KAT
	//
	// INS: 0x22
	// P1/P2: 0x41A6
	// Data: 0x91 - Ephemeral Public Key (mandatory)
	//       0x84 - KeyId			     (conditional)		<-- if multiple public keys are available
	//
	// Exp Rsp: 9000
	//			Exp errors: 6A80 / ...

	var nodes *tlv.TlvNodes = &tlv.TlvNodes{}

	nodes.AddNode(tlv.NewTlvSimpleNode(0x91, cryptoutils.EncodeX962EcPoint(*curve, termKeypair.Pub)))

	// specify key-id (if required)
	if caInfo.KeyId != nil {
		nodes.AddNode(tlv.NewTlvSimpleNode(0x84, caInfo.KeyId.Bytes()))
	}

	// MSE:Set KAT (0x41A6: Set Key Agreement Template for computation)
	// NB same as 'MseSetAT'
	err := (*chipAuth.nfcSession).MseSetAT(0x41, 0xA6, nodes.Encode())
	if err != nil {
		return fmt.Errorf("[doMseSetKAT] MseSetAT error: %w", err)
	}

	return nil
}

func (chipAuth *ChipAuth) doMseSetAT(caInfo *document.ChipAuthenticationInfo) error {
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

	var nodes *tlv.TlvNodes = &tlv.TlvNodes{}

	nodes.AddNode(tlv.NewTlvSimpleNode(0x80, oid.OidBytes(caInfo.Protocol)))
	// specify key-id (if required)
	if caInfo.KeyId != nil {
		nodes.AddNode(tlv.NewTlvSimpleNode(0x84, caInfo.KeyId.Bytes()))
	}

	// MSE:Set AT (0x41A4: Chip Authentication)
	err := (*chipAuth.nfcSession).MseSetAT(0x41, 0xA4, nodes.Encode())

	return err
}

func (chipAuth *ChipAuth) doGeneralAuthenticate(curve *elliptic.Curve, termKeypair cryptoutils.EcKeypair) error {
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

	rApduBytes, err := (*chipAuth.nfcSession).GeneralAuthenticate(false, encodeDynAuthData(0x80, cryptoutils.EncodeX962EcPoint(*curve, termKeypair.Pub)))
	if err != nil {
		return fmt.Errorf("[doGeneralAuthenticate] GeneralAuthenticate error: %w", err)
	}

	slog.Debug("doGeneralAuthenticate", "rApdu-bytes", utils.BytesToHex(rApduBytes))

	// verify that the response includes a 7C tag
	{
		tmpNodes, err := tlv.Decode(rApduBytes)
		if err != nil {
			return fmt.Errorf("[doGeneralAuthenticate] tlv.Decode error: %w", err)
		}
		if !tmpNodes.NodeByTag(0x7C).IsValidNode() {
			return fmt.Errorf("[doGeneralAuthenticate] missing 7C tag in response (rspBytes:%x)", rApduBytes)
		}
	}

	return nil
}

func deriveSessionKeys(curve *elliptic.Curve, termKeypair cryptoutils.EcKeypair, chipPubKey *cryptoutils.EcPoint, caAlgInfo *CaAlgorithmInfo) (ksEnc []byte, ksMac []byte) {
	k := cryptoutils.DoEcDh(termKeypair.Pri, chipPubKey, *curve)
	sharedSecret := k.X.Bytes()
	ksEnc = cryptoutils.KDF(sharedSecret, cryptoutils.KDF_COUNTER_KSENC, caAlgInfo.cipherAlg, caAlgInfo.keySizeBits)
	ksMac = cryptoutils.KDF(sharedSecret, cryptoutils.KDF_COUNTER_KSMAC, caAlgInfo.cipherAlg, caAlgInfo.keySizeBits)
	slog.Debug("deriveSessionKeys", "sharedSecret", utils.BytesToHex(sharedSecret), "ksEnc", utils.BytesToHex(ksEnc), "ksMac", utils.BytesToHex(ksMac))
	return ksEnc, ksMac
}

// performs Chip Authentication in ECDH mode
// NB we currently implement the AES (2) APDU approach, which should also work for TDES
//   - we also have special-case handling where we use MSE-SetKAT if the algorithm was inferred and the mode is 3DES-CBC
func (chipAuth *ChipAuth) doCaEcdh(params *ChipAuthParams) (evidence *caEcdhEvidence, err error) {
	slog.Debug("doCaEcdh", "OID", params.Info.Protocol.String())

	var curve *elliptic.Curve
	var chipPubKey *cryptoutils.EcPoint
	curve, chipPubKey, err = params.PubKeyInfo.ChipAuthenticationPublicKey.EcCurveAndPubKey(true)
	if err != nil {
		return nil, fmt.Errorf("[doCaEcdh] EcCurveAndPubKey error: %w", err)
	}

	slog.Debug("doCaEcdh", "chipPubKey", chipPubKey.String())

	// generate ephemeral key
	var termKeypair cryptoutils.EcKeypair = chipAuth.keyGeneratorEc(*curve)

	evidence = &caEcdhEvidence{
		termPri:    bytes.Clone(termKeypair.Pri),
		termPubKey: cryptoutils.EncodeX962EcPoint(*curve, termKeypair.Pub),
	}

	slog.Debug("doCaEcdh", "algInferred", params.AlgInferred)

	if params.AlgInferred && params.Info.Protocol.Equal(oid.OidCaEcdh3DesCbcCbc) {
		err = chipAuth.doMseSetKAT(curve, termKeypair, params.Info)
		if err != nil {
			return nil, fmt.Errorf("[doCaEcdh] doMseSetKAT error: %w", err)
		}
	} else {
		err = chipAuth.doMseSetAT(params.Info)
		if err != nil {
			return nil, fmt.Errorf("[doCaEcdh] doMseSetAT error: %w", err)
		}

		err = chipAuth.doGeneralAuthenticate(curve, termKeypair)
		if err != nil {
			return nil, fmt.Errorf("[doCaEcdh] doGeneralAuthenticate error: %w", err)
		}
	}

	ksEnc, ksMac := deriveSessionKeys(curve, termKeypair, chipPubKey, params.AlgInfo)

	// setup secure-messaging
	// NB no need to set SSC for ChipAuth
	slog.Debug("doCaECdh - Setup Secure Messaging")
	{
		var err error

		sm, err := iso7816.NewSecureMessaging(params.AlgInfo.cipherAlg, ksEnc, ksMac)
		if err != nil {
			return nil, fmt.Errorf("[doCaEcdh] NewSecureMessaging error: %w", err)
		}
		(*chipAuth.nfcSession).SetSecureMessaging(sm)
	}

	/*
	* Chip Authentication has completed and we've setup/updated Secure Messaging accordingly
	* **BUT** we don't know whether it was really successful until we perform an APDU with the new
	* Secure Messaging, so we perform a lightweight APDU (Select EF - DG14) to confirm success.
	 */

	slog.Debug("doCaECdh - Select EF (DG14) - to verify ChipAuth")
	{
		const MRTDFileIdDG14 = uint16(0x010E)

		selected, err := (*chipAuth.nfcSession).SelectEF(MRTDFileIdDG14)
		if err != nil {
			return nil, fmt.Errorf("[doCaEcdh] SelectEF(DG14) error: %w", err)
		}
		if !selected {
			return nil, fmt.Errorf("[doCaEcdh] unable to select DG14 after performing CA")
		}
	}

	// capture the SM-encrypted RAPDU and the post-decode SSC from the verification SelectEF
	lastApdu := (*chipAuth.nfcSession).LastApdu()
	if lastApdu != nil && lastApdu.Child != nil {
		evidence.smRapdu = bytes.Clone(lastApdu.Child.Rx)
	}
	if sm := (*chipAuth.nfcSession).SM(); sm != nil {
		evidence.smSsc = bytes.Clone(sm.SSC())
	}

	return evidence, nil
}

// VerifyEvidence verifies the internal cryptographic consistency of Chip Authentication
// evidence captured during a previous NFC session. It requires only the Document (which
// supplies the chip's EC public key from DG14).
//
// Verification steps:
//  1. Resolve CA parameters from the Document (algorithm, chip public key, curve).
//  2. Reconstruct the terminal keypair from the evidence.
//  3. Re-derive the shared secret and session keys (ksEnc, ksMac) via ECDH + KDF.
//  4. Verify the SM MAC on the captured RAPDU using ksMac.
//  5. Confirm the decrypted RAPDU status is 9000 (success).
//
// Security limitation: this function cannot prove a genuine chip was present. The CA
// shared secret is sharedSecret = TermPri·chipPubKey = skCA_IC·TermPub — both the
// terminal and the chip can compute the same value. Because TermPri is known to the
// terminal and chipPubKey is public (from DG14), a forger can derive ksMac without
// holding skCA_IC and construct a MAC-valid SmRapdu with status 9000. The live session
// is secure because the chip must decrypt the SM-protected command (requiring skCA_IC)
// before it can respond, but the command is not captured in the evidence, so the
// verifier cannot check this.
//
// This function is therefore best understood as tamper-detection on evidence captured
// by a trusted terminal: any post-capture modification to any field breaks the MAC
// chain. It must be paired with Passive Authentication (binding DG14 to a CSCA chain)
// and trust in the capturing terminal for the overall claim to be meaningful.
//
// This function does not perform replay detection. Applications should implement
// their own checks (e.g. tracking previously seen evidence) to prevent a valid
// evidence payload from being replayed.
const maxEvidenceFieldLen = 1024

func VerifyEvidence(doc *document.Document, evidence *document.ChipAuthEvidence) (*document.ChipAuthResult, error) {
	if evidence == nil {
		return nil, fmt.Errorf("[VerifyEvidence] evidence is nil")
	}

	if len(evidence.TermPri) == 0 || len(evidence.TermPubKey) == 0 || len(evidence.SmRapdu) == 0 {
		return nil, fmt.Errorf("[VerifyEvidence] evidence has empty field(s)")
	}

	if len(evidence.TermPri) > maxEvidenceFieldLen ||
		len(evidence.TermPubKey) > maxEvidenceFieldLen ||
		len(evidence.SmRapdu) > maxEvidenceFieldLen {
		return nil, fmt.Errorf("[VerifyEvidence] evidence field exceeds maximum length (%d)", maxEvidenceFieldLen)
	}

	params, err := selectChipAuthParams(doc)
	if err != nil {
		return nil, fmt.Errorf("[VerifyEvidence] selectChipAuthParams error: %w", err)
	}

	var curve *elliptic.Curve
	var chipPubKey *cryptoutils.EcPoint
	curve, chipPubKey, err = params.PubKeyInfo.ChipAuthenticationPublicKey.EcCurveAndPubKey(true)
	if err != nil {
		return nil, fmt.Errorf("[VerifyEvidence] EcCurveAndPubKey error: %w", err)
	}

	// reconstruct the terminal keypair from the evidence
	termPub, err := cryptoutils.DecodeX962EcPoint(*curve, evidence.TermPubKey)
	if err != nil {
		return nil, fmt.Errorf("[VerifyEvidence] DecodeX962EcPoint error: %w", err)
	}

	// verify that the terminal public key is consistent with the private key
	expX, expY := (*curve).ScalarBaseMult(evidence.TermPri)
	if termPub.X.Cmp(expX) != 0 || termPub.Y.Cmp(expY) != 0 {
		return nil, fmt.Errorf("[VerifyEvidence] terminal public key does not match private key")
	}

	termKeypair := cryptoutils.EcKeypair{
		Pri: evidence.TermPri,
		Pub: termPub,
	}

	ksEnc, ksMac := deriveSessionKeys(curve, termKeypair, chipPubKey, params.AlgInfo)

	sm, err := iso7816.NewSecureMessaging(params.AlgInfo.cipherAlg, ksEnc, ksMac)
	if err != nil {
		return nil, fmt.Errorf("[VerifyEvidence] NewSecureMessaging error: %w", err)
	}

	// Set SSC to (captured − 1) so sm.Decode (which increments before verifying) reaches
	// the exact SSC that was in effect when SmRapdu was captured. Legacy bundles without
	// SmSsc default to 1, which is correct when SelectEF was the first SM command (SSC=2).
	sscInit := big.NewInt(1)
	if len(evidence.SmSsc) > 0 {
		sscInit.Sub(new(big.Int).SetBytes(evidence.SmSsc), big.NewInt(1))
	}
	ssc := make([]byte, len(sm.SSC()))
	sscInit.FillBytes(ssc)
	if err = sm.SetSSC(ssc); err != nil {
		return nil, fmt.Errorf("[VerifyEvidence] SetSSC error: %w", err)
	}

	rApdu, err := sm.Decode(evidence.SmRapdu)
	if err != nil {
		return nil, fmt.Errorf("[VerifyEvidence] SM MAC verification failed: %w", err)
	}

	if !rApdu.IsSuccess() {
		return nil, fmt.Errorf("[VerifyEvidence] RAPDU status is not success (status:%04x)", rApdu.Status)
	}

	return &document.ChipAuthResult{Success: true, Evidence: evidence}, nil
}

// dynamic authentication data - (TLV) 7C <tag> <data>
func encodeDynAuthData(tag byte, data []byte) []byte {
	node := tlv.NewTlvConstructedNode(0x7C)
	node.AddChild(tlv.NewTlvSimpleNode(tlv.TlvTag(tag), data))
	return node.Encode()
}
