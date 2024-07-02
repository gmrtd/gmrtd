package gmrtd

import (
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"slices"

	"github.com/ebfe/brainpool"
)

// TODO
//
// ASN1 format found in 'SpecifiedECDomain'
// https://www.itu.int/ITU-T/formal-language/itu-t/x/x894/2018-cor1/ANSI-X9-62.html
//
// also need to look at 9303p11.. Part 11 - Chip Authentication
//	example is taking from CardSecurity... but also used std domain params instead of explicit.. so should support both?

type ChipAuth struct {
	keyGeneratorEc KeyGeneratorEcFn
}

func NewChipAuth() *ChipAuth {
	var chipAuth ChipAuth
	chipAuth.keyGeneratorEc = KeyGeneratorEc
	return &chipAuth
}

func (chipAuth *ChipAuth) doChipAuth(nfc *NfcSession, doc *Document) (err error) {
	if nfc.sm != nil {
		slog.Debug("doChipAuth", "SM(pre)", nfc.sm.String())
	}

	// skip if we have already performed chip authentication
	if doc.ChipAuthStatus != CHIP_AUTH_STATUS_NONE {
		return nil
	}

	// skip if DG14 is missing
	if doc.Dg14 == nil {
		// NB consider this an error as DG14 is mandatory and this should only occur if it's called in the wrong sequence
		//	  i.e. before DGs are read
		return fmt.Errorf("cannot consider CA due to missing DG14")
	}

	var caInfo *ChipAuthenticationInfo = selectCAInfo(doc)
	if caInfo == nil {
		return nil
	}

	var caAlgInfo *CaAlgorithmInfo
	caAlgInfo, err = getAlgInfo(caInfo.Protocol)
	if err != nil {
		return err
	}

	var caPubKeyInfo *ChipAuthenticationPublicKeyInfo = selectCAPubKeyInfo(caInfo, caAlgInfo, doc)
	if caPubKeyInfo == nil {
		return fmt.Errorf("chipAuth: unable to select public-key info") // TODO - what data to log?
	}

	// process based on the type of key (DH/ECDH)
	if caPubKeyInfo.Protocol.Equal(oidPkDh) {
		// DH
		return fmt.Errorf("chipAuth: DH not currently supported") // TODO - what to log?
	} else if caPubKeyInfo.Protocol.Equal(oidPkEcdh) {
		// ECDH
		err = chipAuth.doCaEcdh(nfc, caInfo, *caAlgInfo, caPubKeyInfo)
		if err != nil {
			return err
		}
		// record chip-auth status
		doc.ChipAuthStatus = CHIP_AUTH_STATUS_CA
	} else {
		return fmt.Errorf("chipAuth: unsupported public key type (OID:%s)", caPubKeyInfo.Protocol.String())
	}

	if nfc.sm != nil {
		slog.Debug("doChipAuth", "SM(post)", nfc.sm.String())
	}

	return nil
}

// selects the 'preferred' CA entry (if any are present)
// returns: nil if none found, otherwise preferred CA entry
func selectCAInfo(doc *Document) *ChipAuthenticationInfo {
	var out *ChipAuthenticationInfo

	for i := range doc.Dg14.SecInfos.ChipAuthInfos {
		// TODO - should pick preferred entry (if multiple).. currently just pick last
		out = &(doc.Dg14.SecInfos.ChipAuthInfos[i])
	}

	return out
}

// selects the public key matching the target OID (i.e. oidPkDh / oidPkEcdh) as well as the 'KeyId' (if specified)
func selectCAPubKeyInfo(caInfo *ChipAuthenticationInfo, caAlgInfo *CaAlgorithmInfo, doc *Document) *ChipAuthenticationPublicKeyInfo {

	for i := range doc.Dg14.SecInfos.ChipAuthPubKeyInfos {
		var curPubKey *ChipAuthenticationPublicKeyInfo = &(doc.Dg14.SecInfos.ChipAuthPubKeyInfos[i])

		if curPubKey.Protocol.Equal(caAlgInfo.targetOid) {
			if caInfo.KeyId == nil {
				// no key-id specified, so good to use any matching public-key
				return curPubKey
			} else {
				// key-id specified, so need to find matching public-key
				if caInfo.KeyId.Cmp(curPubKey.KeyId) == 0 { // TODO - nil check on curPubKey.keyId? is it required?
					return curPubKey
				}
			}
		}
	}

	// TODO - why not return error?
	return nil
}

// TODO - have a weighting (like pace) so we can pick the best (if multiple exist)
type CaAlgorithmInfo struct {
	targetOid   asn1.ObjectIdentifier
	cipherAlg   BlockCipherAlg
	keySizeBits int
}

var caAlgInfo = map[string]CaAlgorithmInfo{
	oidCaDh3DesCbcCbc.String():    {oidPkDh, TDES, 112},
	oidCaDhAesCbcCmac128.String(): {oidPkDh, AES, 128},
	oidCaDhAesCbcCmac192.String(): {oidPkDh, AES, 192},
	oidCaDhAesCbcCmac256.String(): {oidPkDh, AES, 256},

	oidCaEcdh3DesCbcCbc.String():    {oidPkEcdh, TDES, 112},
	oidCaEcdhAesCbcCmac128.String(): {oidPkEcdh, AES, 128},
	oidCaEcdhAesCbcCmac192.String(): {oidPkEcdh, AES, 192},
	oidCaEcdhAesCbcCmac256.String(): {oidPkEcdh, AES, 256},
}

// TODO - return error?
func getAlgInfo(oid asn1.ObjectIdentifier) (*CaAlgorithmInfo, error) {
	out, ok := caAlgInfo[oid.String()]

	if !ok {
		return nil, fmt.Errorf("getAlgInfo: OID not found (%s)", oid.String())
	}

	return &out, nil
}

// performs Chip Authentication in ECDH mode
// NB does NOT update doc.ChipAuthStatus, caller is expected to do this!
// NB we currently implement the AES (2) APDU approach, which should also work for TDES (i.e. we don't implement MSE:Set KAT just for TDES)
func (chipAuth *ChipAuth) doCaEcdh(nfc *NfcSession, caInfo *ChipAuthenticationInfo, caAlgInfo CaAlgorithmInfo, caPubKeyInfo *ChipAuthenticationPublicKeyInfo) (err error) {
	slog.Debug("doCaEcdh", "OID", caInfo.Protocol.String())

	specDomain := parseECSpecifiedDomain(&(caPubKeyInfo.ChipAuthenticationPublicKey.Algorithm))

	curve, err := getECCurveForSpecifiedDomain(specDomain)
	if err != nil {
		return err
	}

	// get the chip's public key
	var chipPubKey *EC_POINT
	{
		var chipPubKeyBytes []byte = caPubKeyInfo.ChipAuthenticationPublicKey.SubjectPublicKey.Bytes
		slog.Debug("doCaEcdh", "chip pubKey", BytesToHex(chipPubKeyBytes))
		chipPubKey = decodeX962EcPoint(curve, chipPubKeyBytes)
	}
	slog.Debug("doCaEcdh", "chipPubKey", chipPubKey.String())

	// generate ephemeral key
	var termPri []byte
	var termPub *EC_POINT
	termPri, termPub = chipAuth.keyGeneratorEc(curve)

	// MSE:Set AT
	//
	// INS: 0x22
	// P1/P2: 0x41A4
	// Data: 0x80 - OID of protocol (mandatory)			<-- caInfo.Protocol
	//		 0x84 - KeyId			(conditional)		<-- if multiple public keys are available
	//
	// Exp Rsp: 9000
	//			Exp errors: 6A80 / 6A88 / ...

	slog.Debug("doCaECdh - MSE:Set AT")
	{
		nodes := NewTlvNodes()
		nodes.AddNode(NewTlvSimpleNode(0x80, oidBytes(caInfo.Protocol)))
		// specify key-id (if required)
		if caInfo.KeyId != nil {
			nodes.AddNode(NewTlvSimpleNode(0x84, caInfo.KeyId.Bytes()))
		}

		// MSE:Set AT (0x41A4: Chip Authentication)
		err = nfc.MseSetAT(0x41, 0xA4, nodes.Encode())
		if err != nil {
			return err
		}
	}

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

	var ksEnc, ksMac []byte

	// TODO - move to func
	slog.Debug("doCaECdh - General Authenticate")
	{
		var rApdu *RApdu = nfc.GeneralAuthenticate(false, encode_7C_XX(0x80, encodeX962EcPoint(curve, termPub)))
		if !rApdu.IsSuccess() {
			return fmt.Errorf("doCaEcdh: General Authenticate failed (Status:%d)", rApdu.Status)
		}

		slog.Debug("doCaEcdh", "rApdu-bytes", BytesToHex(rApdu.Data))

		// TODO - should validate the response... as 7C is mandatory
		//			AT passport simply return 7C00

		// 3. Both the eMRTD chip and the terminal compute the following:
		// a) The shared secret K = KA(SKIC, PKDH,IFD, DIC) = KA(SKDH,IFD, PKIC, DIC)
		var k *EC_POINT = doEcDh(termPri, chipPubKey, curve)

		// NB secret is just based on 'x'
		sharedSecret := k.x.Bytes()

		slog.Debug("doCaEcdh", "sharedSecret", BytesToHex(sharedSecret))

		// b) The session keys KSMAC = KDFMAC(K) and KSEnc = KDFEnc(K) derived from K for Secure Messaging.
		{
			ksEnc = KDF(sharedSecret, KDF_COUNTER_KSENC, caAlgInfo.cipherAlg, caAlgInfo.keySizeBits)
			ksMac = KDF(sharedSecret, KDF_COUNTER_KSMAC, caAlgInfo.cipherAlg, caAlgInfo.keySizeBits)

			slog.Debug("doCaEcdh", "ksEnc", BytesToHex(ksEnc), "ksMac", BytesToHex(ksMac))
		}

	}

	// setup secure-messaging
	// NB no need to set SSC for ChipAuth
	slog.Debug("doCaECdh - Setup Secure Messaging")
	{
		var err error

		nfc.sm, err = NewSecureMessaging(caAlgInfo.cipherAlg, ksEnc, ksMac)
		if err != nil {
			return err
		}
	}

	// Chip Authentication has completed and we've setup/updated Secure Messaging accordingly
	// **BUT** we don't know whether it was really successful until we perform an APDU with the new
	// Secure Messaging, so we perform a lightweight APDU (Select EF - DG14) to confirm success.

	slog.Debug("doCaECdh - Select EF (DG14) - to verify ChipAuth")
	{
		selected, err := nfc.SelectEF(MRTDFileIdDG14)
		if err != nil {
			// TODO - may want to wrap error, as this indicates CA failure, but underlying error is probably SM related
			return err
		}
		if !selected {
			return fmt.Errorf("unable to select DG14 after performing CA")
		}
	}

	return nil
}

// https://www.itu.int/ITU-T/formal-language/itu-t/x/x894/2018-cor1/ANSI-X9-62.html
//
// -- Type (parameterized) to indicate the hash function with
// -- the OID ecdsa-with-Specified
// HashAlgorithm::= AlgorithmIdentifier {{ ANSIX9HashFunctions }}
//
// -- Finite field element
// FieldElement ::= OCTET STRING
//
// -- Finite fields have a type (prime or binary) and parameters (size and basis)
// FieldID { FIELD-ID:IOSet } ::= SEQUENCE {-- Finite field
// 	fieldType		FIELD-ID.&id({IOSet}),
// 	parameters		FIELD-ID.&Type({IOSet}{@fieldType})
// 	}
// 	-- ============================================
// 	-- Elliptic Curve Points (see  E.6)
// 	-- ============================================
// 	ECPoint ::= OCTET STRING
// 	-- ============================================
// 	-- Elliptic Curve Domain Parameters (see  E.7)
// 	-- ============================================
// 	-- Identifying an elliptic curve by its coefficients (and optional seed)
// 	Curve ::= SEQUENCE {
// 	a		FieldElement, -- Elliptic curve coefficient a
// 	b		FieldElement, -- Elliptic curve coefficient b
// 	seed	BIT STRING OPTIONAL
// 	-- Shall be present if used in SpecifiedECDomain with version of
// 	-- ecdpVer2 or ecdpVer3
// 	}
// 	-- Type used to control version of EC domain parameters
// 	SpecifiedECDomainVersion ::= INTEGER { ecdpVer1(1) , ecdpVer2(2) , ecdpVer3(3) }
// 	-- Identifying elliptic curve domain parameters explicitly with this type
// 	SpecifiedECDomain ::= SEQUENCE {
// 	version		SpecifiedECDomainVersion ( ecdpVer1 | ecdpVer2 | ecdpVer3 ),
// 	fieldID		FieldID {{FieldTypes}},
// 	curve		Curve,
// 	base			ECPoint, -- Base point G
// 	order		INTEGER, -- Order n of the base point
// 	cofactor		INTEGER OPTIONAL, -- The integer h = #E(Fq)/n
// 	hash			HashAlgorithm OPTIONAL,
// 	... -- Additional parameters may be added
// 	}

// TODO - consider aligning above to RFC-3279.. ECParameters ?

type ECCurve struct {
	A    []byte
	B    []byte
	Seed asn1.BitString `asn1:"optional"`
}

type ECField struct {
	FieldType  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

type ECSpecifiedDomain struct {
	Version  int
	FieldId  ECField
	Curve    ECCurve
	Base     []byte
	Order    *big.Int
	Cofactor *big.Int
	Hash     asn1.ObjectIdentifier `asn1:"optional"`
}

// parse ecPublicKey ASN1 object (aka EC Specified Domain)
func parseECSpecifiedDomain(algIdentifier *AlgorithmIdentifier) (out *ECSpecifiedDomain) {
	slog.Debug("parseECSpecifiedDomain", "Algorithm Identifier", algIdentifier)

	if !algIdentifier.Algorithm.Equal(oidEcPublicKey) {
		// TODO - should we panic?
		log.Panicf("expected ecPublicKey OID")
	}

	out = new(ECSpecifiedDomain)

	slog.Debug("parseECSpecifiedDomain", "Parameters(bytes)", BytesToHex(algIdentifier.Parameters.FullBytes))

	// TODO - are we sure partial flag actually works.. asn1 decode seems to be quite happy skipping fields
	err := parseAsn1(algIdentifier.Parameters.FullBytes, true, out) // TODO - NB may have extra field after
	if err != nil {
		log.Panicf("parseSubjectPublicKey err:%s", err)
	}

	// TODO - any other data checks?
	if !out.FieldId.FieldType.Equal(oidPrimeField) {
		log.Panicf("PrimeField OID expected")
	}

	slog.Debug("parseECSpecifiedDomain",
		"Version", out.Version,
		"FieldId.FieldType", out.FieldId.FieldType.String(),
		"FieldId.Parameters", BytesToHex(out.FieldId.Parameters.Bytes),
		"Curve.A", BytesToHex(out.Curve.A),
		"Curve.B", BytesToHex(out.Curve.B),
		"Curve.Seed", BytesToHex(out.Curve.Seed.Bytes),
		"Base", BytesToHex(out.Base),
		"Order", BytesToHex(out.Order.Bytes()),
		"CoFactor", BytesToHex(out.Cofactor.Bytes()),
	)

	return
}

var caEcArr []elliptic.Curve = []elliptic.Curve{
	elliptic.P224(),
	elliptic.P256(),
	elliptic.P384(),
	elliptic.P521(),
	brainpool.P160r1(),
	brainpool.P192r1(),
	brainpool.P224r1(),
	brainpool.P256r1(),
	brainpool.P320r1(),
	brainpool.P384r1(),
	brainpool.P512r1(),
}

func getECCurveForSpecifiedDomain(specDomain *ECSpecifiedDomain) (elliptic.Curve, error) {
	// Technically we should support 'total' cryptographic agility and allow the MRTD to
	// dictate any DH/ECDH parameters of its choosing. However, it's more likely that MRTDs
	// are referencing well-known parameters instead of using random (and potentially unsafe)
	// settings, so we intentionally support a limited subset and will evaluate this over time.

	slog.Debug("getECCurveForSpecifiedDomain", "Params", BytesToHex(specDomain.FieldId.Parameters.Bytes))

	// look for matching 'standard' curve
	// NB we currently expect the use of standard curve, we may need to support custom curves in the future (but hopefully not)
	for i := 0; i < len(caEcArr); i++ {
		var ec elliptic.Curve = caEcArr[i]

		// TODO - should be looking at more than Params.P, but should be good for now
		if slices.Equal(ec.Params().P.Bytes(), specDomain.FieldId.Parameters.Bytes[1:]) { // TODO - highlight significance of [1:]
			return ec, nil
		}
	}

	return nil, fmt.Errorf("unsupported CA EC (Params:%x)", specDomain.FieldId.Parameters.Bytes) // TODO - may want to record other params also
}
