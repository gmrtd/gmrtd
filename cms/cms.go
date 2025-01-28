// Package cms implements the 'Cryptographic Message Syntax' (CMS) as described in RFC-5652.
//
// Support is also provided for X509 (RFC-5652)
//
// This package provides basic support for CMS/X509 to support MRTD use-cases.
package cms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"slices"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
	"github.com/osanderson/brainpool"
)

// TODO - no attempt made for revocation checking

type SubjectPublicKeyInfo struct {
	Algorithm        AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type SignedData struct {
	Oid asn1.ObjectIdentifier ``
	SD2 SignedData2           `asn1:"explicit,tag:0"`
}

type SignedData2 struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	Content          EncapContentInfo      ``
	Certificates     asn1.RawValue         `asn1:"optional,tag:0"`
	CRLs             []asn1.RawValue       `asn1:"optional,set,tag:1"`
	SignerInfos      []SignerInfo          `asn1:"set"`
}

type SignerInfo struct {
	Raw                       asn1.RawContent
	Version                   int                 `asn1:"default:1"`
	IssuerAndSerialNumber     IssuerAndSerial     `asn1:"optional"` // optional for DE masterlist
	DigestAlgorithm           AlgorithmIdentifier `asn1:"optional"` // optional for DE masterlist
	AuthenticatedAttributes   AttributeList       `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm AlgorithmIdentifier `asn1:"optional"` // optional for DE masterlist
	EncryptedDigest           []byte              `asn1:"optional"` // optional for DE masterlist
	UnauthenticatedAttributes AttributeList       `asn1:"optional,tag:1"`
}

type IssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type Attribute struct {
	Raw    asn1.RawContent
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}
type AttributeList []Attribute

// returns: nil if no matching attribute found
func (attributes AttributeList) GetByOID(oid asn1.ObjectIdentifier) *Attribute {
	for i := 0; i < len(attributes); i++ {
		if oid.Equal(attributes[i].Type) {
			return &(attributes[i])
		}
	}

	return nil
}

// gets the ASN1 encoded attribute data wrapped in a parent 'SET OF' (0x31) tag
// NB builds using the 'Raw' field, so any changes to the low-level fields will not be reflected
func (attributes AttributeList) GetSetOfAsnBytes() []byte {
	// A separate encoding
	// of the signedAttrs field is performed for message digest calculation.
	// The IMPLICIT [0] tag in the signedAttrs is not used for the DER
	// encoding, rather an EXPLICIT SET OF tag is used.  That is, the DER
	// encoding of the EXPLICIT SET OF tag, rather than of the IMPLICIT [0]
	// tag, MUST be included in the message digest calculation along with
	// the length and content octets of the SignedAttributes value.
	//
	// https://datatracker.ietf.org/doc/html/rfc5652#section-5.4

	var data []byte

	for i := 0; i < len(attributes); i++ {
		data = append(data, attributes[i].Raw...)
	}

	// wrap with explicit 'SET OF' (0x31) tag
	data = tlv.NewTlvSimpleNode(0x31, data).Encode()

	return data
}

type EncapContentInfo struct {
	Raw          asn1.RawContent
	EContentType asn1.ObjectIdentifier ``
	EContent     []byte                `asn1:"explicit,tag:0"` // e.g. LDSSecurityObject / SecurityInfos
}

func ParseSignedData(data []byte) (*SignedData, error) {
	var err error
	var signedData SignedData

	err = utils.ParseAsn1(data, true, &signedData)
	if err != nil {
		return nil, fmt.Errorf("asn1 parsing error: %s", err)
	}

	// TODO - we're not currently verifying the data... e.g. do we have the correct OIDs

	return &signedData, nil
}

func ParseCertificate(data []byte) (*Certificate, error) {
	var err error
	var certificate Certificate

	err = utils.ParseAsn1(data, false, &certificate)
	if err != nil {
		return nil, fmt.Errorf("asn1 parsing error: %s", err)
	}

	// TODO - data verification...

	return &certificate, nil
}

type Certificate struct {
	Raw                asn1.RawContent
	TbsCertificate     TBSCertificate
	SignatureAlgorithm AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type Extensions []Extension

type AuthorityKeyIdentifier struct {
	KeyIdentifier             []byte          `asn1:"optional,implicit,tag:0"`
	AuthorityCertIssuer       asn1.RawContent `asn1:"optional,implicit,tag:1"`
	AuthorityCertSerialNumber asn1.RawContent `asn1:"optional,implicit,tag:2"`
}

type SubjectKeyIdentifier []byte

func (extensions Extensions) GetAuthorityKeyIdentifier() *AuthorityKeyIdentifier {
	for i := 0; i < len(extensions); i++ {
		if extensions[i].ObjectId.Equal(oid.OidAuthorityKeyIdentifier) {
			var out AuthorityKeyIdentifier

			err := utils.ParseAsn1(extensions[i].ExtnValue.Bytes, false, &out)
			if err != nil {
				log.Panicf("error: %s", err)
			}

			return &out
		}
	}

	return nil
}

func (extensions Extensions) GetSubjectKeyIdentifier() *SubjectKeyIdentifier {
	for i := 0; i < len(extensions); i++ {
		if extensions[i].ObjectId.Equal(oid.OidSubjectKeyIdentifier) {
			var out SubjectKeyIdentifier

			err := utils.ParseAsn1(extensions[i].ExtnValue.Bytes, false, &out)
			if err != nil {
				log.Panicf("error: %s", err)
			}

			return &out
		}
	}

	return nil
}

// TODO - handlers for other extensions... key-usage (sign,..)... CSCA: privateKeyUsagePeriod, id-ce-keyUsage (for CA detection?)

type TBSCertificate struct {
	Raw                  asn1.RawContent
	Version              int `asn1:"explicit,default:1,tag:0"`
	SerialNumber         *big.Int
	Signature            AlgorithmIdentifier
	Issuer               asn1.RawValue
	Validity             Validity
	Subject              asn1.RawValue
	SubjectPublicKeyInfo asn1.RawValue
	IssuerUniqueId       asn1.BitString `asn1:"implicit,optional,tag:1"`
	SubjectUniqueId      asn1.BitString `asn1:"implicit,optional,tag:2"`
	Extensions           Extensions     `asn1:"explicit,optional,tag:3"`
}

type Validity struct {
	NotBefore asn1.RawValue
	NotAfter  asn1.RawValue
}

type Extension struct {
	Raw       asn1.RawContent
	ObjectId  asn1.ObjectIdentifier
	Critical  asn1.Flag `asn1:"optional,default:false"`
	ExtnValue asn1.RawValue
}

/*

Certificate  ::=  SEQUENCE  {
	tbsCertificate       TBSCertificate,
	signatureAlgorithm   AlgorithmIdentifier,
	signatureValue       BIT STRING  }

	TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3




Cooper, et al.              Standards Track                    [Page 16]

RFC 5280            PKIX Certificate and CRL Profile            May 2008


        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }

		CertificateSerialNumber  ::=  INTEGER

		Validity ::= SEQUENCE {
			notBefore      Time,
			notAfter       Time }

	   Time ::= CHOICE {
			utcTime        UTCTime,
			generalTime    GeneralizedTime }

	   UniqueIdentifier  ::=  BIT STRING

	   SubjectPublicKeyInfo  ::=  SEQUENCE  {
			algorithm            AlgorithmIdentifier,
			subjectPublicKey     BIT STRING  }

	   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

	   Extension  ::=  SEQUENCE  {
			extnID      OBJECT IDENTIFIER,
			critical    BOOLEAN DEFAULT FALSE,
			extnValue   OCTET STRING
						-- contains the DER encoding of an ASN.1 value
						-- corresponding to the extension type identified
						-- by extnID
			}
*/

func (sd *SignedData2) Verify(certPool *CertPool) (certChain [][]byte, err error) {
	slog.Debug("SignedData.Verify")

	/*
		- for each signer-info
			- determine the hash alg (siHashAlg)
			- determine the context type that is hashed (e.g. ldsSecurityObject for SOD)
			- get the data that is hashed
			- verify siHash matches the original data (content)
			- verify other info (?TBC?)										<---------------- TODO (e.g. key-perms, signing-time)
			- cert(chain) validation of the signer-info signature
	*/

	var cert *Certificate

	cert, err = ParseCertificate(sd.Certificates.Bytes)
	if err != nil {
		return certChain, fmt.Errorf("(Verify) parseCertificate Error: %w", err)
	}

	slog.Debug("Verify", "SubjectPublicKey", utils.BytesToHex(cert.TbsCertificate.SubjectPublicKeyInfo.FullBytes))

	// for-each signer-info
	// NB we only expect 1, but support >1
	for siIdx := 0; siIdx < len(sd.SignerInfos); siIdx++ {
		var si *SignerInfo = &(sd.SignerInfos[siIdx])

		aaContentType := si.AuthenticatedAttributes.GetByOID(oid.OidContentType)
		aaMessageDigest := si.AuthenticatedAttributes.GetByOID(oid.OidMessageDigest)
		if aaContentType == nil || aaMessageDigest == nil {
			return certChain, fmt.Errorf("(Verify) Expected Authenticated-Attribute(s) missing (Content-Type, Message-Digest)")
		}

		var aaContentTypeOID asn1.ObjectIdentifier = asn1decodeOid(aaContentType.Values.Bytes)
		var aaMessageDigestHash []byte = asn1decodeBytes(aaMessageDigest.Values.Bytes)

		slog.Debug("Verify", "AA Content-Type", aaContentTypeOID.String())
		slog.Debug("Verify", "AA Message-Digest", utils.BytesToHex(aaMessageDigestHash))

		// verify Content OID matches Authenticated-Attribute (Content Type)
		if !aaContentTypeOID.Equal(sd.Content.EContentType) {
			return certChain, fmt.Errorf("(Verify) Content-Type-OID (%s) differs to Authenticated-Attribute (%s)", sd.Content.EContentType.String(), aaContentTypeOID.String())
		}

		var contentHash []byte = cryptoutils.CryptoHashByOid(si.DigestAlgorithm.Algorithm, sd.Content.EContent)
		slog.Debug("Verify", "ContentHash", utils.BytesToHex(contentHash))

		// TODO - different process if auth-attr are NOT present... so maybe this is optional?
		//			- sig input would be slightly different
		//			- most of this only applies if we have auth-attributes present... should check even if not handling today
		//				basically if not present then sig is based on content hash.. if present then based on auth-attr and also
		//				need to check hash in  auth-attr (as per current)
		//
		//	5.4.  Message Digest Calculation Process (RFC5652)
		if !bytes.Equal(contentHash, aaMessageDigestHash) {
			// invalid content hash
			slog.Debug("Verify - invalid content hash", "contentHash", utils.BytesToHex(contentHash), "aaMessageDigestHash", utils.BytesToHex(aaMessageDigestHash))
			return certChain, fmt.Errorf("(Verify) Invalid content hash (contentHash:%x, aaMessageDigestHash:%x)", contentHash, aaMessageDigestHash)
		}

		var dataToHash []byte = si.AuthenticatedAttributes.GetSetOfAsnBytes()
		slog.Debug("Verify", "dataToHash", utils.BytesToHex(dataToHash))

		digestAlg := si.DigestAlgorithm.Algorithm

		var digest []byte = cryptoutils.CryptoHashByOid(digestAlg, dataToHash)
		slog.Debug("Verify", "digest", utils.BytesToHex(digest))

		/*
		* Verify the SignedInfo signature (against the PublicKey in the Certificate)
		 */

		err = VerifySignature(cert.TbsCertificate.SubjectPublicKeyInfo.FullBytes, digestAlg, digest, si.DigestEncryptionAlgorithm.Algorithm, si.EncryptedDigest)
		if err != nil {
			return certChain, fmt.Errorf("(Verify) error: %w", err)
		}

		/*
		* verify the cert/chain
		* so far we've just verified the signedData and enveloped-data we haven't actually verified that the certificate is signed by someone we trust
		 */
		certChain, err = cert.Verify(certPool)
		if err != nil {
			return certChain, fmt.Errorf("(Verify) error: %w", err)
		}

		// record cert
		certChain = append(certChain, bytes.Clone(cert.Raw))
	}

	return certChain, nil
}

func (cert *Certificate) Verify(certPool *CertPool) (certChain [][]byte, err error) {
	// TODO - currently just gets immediate parent.. doesn't move up a deeper cert chain
	// TODO - currently just verifies the signature... doesn't check anything else... e.g. signing-time-validity... country/name
	//			see 9303p10 5.1 Passive Authentication for detailed overview

	// get the parent certificate (authority) key identifier
	var aki *AuthorityKeyIdentifier
	{
		aki = cert.TbsCertificate.Extensions.GetAuthorityKeyIdentifier()
	}
	if aki == nil {
		return certChain, fmt.Errorf("(Certificate.Verify) AKI missing from cert (%x)", cert.Raw)
	}

	// get any matching parent certificates
	// NB often >1 due to cross-signing in master-list
	parentCerts := certPool.GetBySki(aki.KeyIdentifier)

	slog.Debug("Certificate.Verify", "ParentCertCnt", len(parentCerts))

	// stop if no parent cert(s) found
	if len(parentCerts) < 1 {
		return certChain, fmt.Errorf("(Certificate.Verify) unable to locate parent certificate (SKI:%x)", aki.KeyIdentifier)
	}

	//slog.Info("CERT.Verify", "Cert", utils.BytesToHex(cert.Raw))

	// test each parent cert until we find one that validates the cert signature
	for i := 0; i < len(parentCerts); i++ {
		var err error

		var digestAlg *asn1.ObjectIdentifier
		digestAlg, err = cert.SignatureAlgorithm.DetermineDigestAlgFromSigAlg()
		if err != nil {
			// ignore error and try other parent certs
			// TODO - should we really be ignoring this error? at least we may want some logging
			continue
		}

		var digest []byte = cryptoutils.CryptoHashByOid(*digestAlg, cert.TbsCertificate.Raw)

		err = VerifySignature(parentCerts[i].TbsCertificate.SubjectPublicKeyInfo.FullBytes, *digestAlg, digest, cert.SignatureAlgorithm.Algorithm, cert.SignatureValue.Bytes)
		if err != nil {
			// ignore error and try other parent certs
			continue
		}

		// TODO - should really continue until we encounter a CA cert
		//			- anything in the CSCA cert-pool is considered a CA.. but code could be more generic

		// record cert
		certChain = append(certChain, bytes.Clone(parentCerts[i].Raw))

		return certChain, nil
	}

	// TODO - still need to match cert-country.. and should also check MRZ country (TBC?)

	return certChain, fmt.Errorf("(Certificate.Verify) signature not verified against matched certificates (matchCnt:%d,aki:%x,cert:%x)", len(parentCerts), aki.KeyIdentifier, cert.Raw)
}

func VerifySignature(pubKeyInfo []byte, digestAlg asn1.ObjectIdentifier, digest []byte, sigAlg asn1.ObjectIdentifier, sig []byte) error {
	var err error

	slog.Debug("VerifySignature", "pubKeyInfo", utils.BytesToHex(pubKeyInfo), "digestAlg", digestAlg.String(), "digest", utils.BytesToHex(digest), "sigAlg", sigAlg.String(), "sig", utils.BytesToHex(sig))

	switch sigAlg.String() {
	/*
	* ECDSA
	 */
	case
		oid.OidEcdsaWithSHA1.String(),
		oid.OidEcdsaWithSHA224.String(),
		oid.OidEcdsaWithSHA256.String(),
		oid.OidEcdsaWithSHA384.String(),
		oid.OidEcdsaWithSHA512.String():
		{
			var pub *ecdsa.PublicKey
			{
				var subPubKeyInfo SubjectPublicKeyInfo = Asn1decodeSubjectPublicKeyInfo(pubKeyInfo)

				var ecCurve *elliptic.Curve
				var ecPoint *cryptoutils.EcPoint
				ecCurve, ecPoint = subPubKeyInfo.GetEcCurveAndPubKey()

				pub = &ecdsa.PublicKey{Curve: *ecCurve, X: ecPoint.X, Y: ecPoint.Y}
			}

			// VerifyASN1: works with non-nist curves (i.e. brainpool) via legacy code (hopefully this doesn't change)
			validSig := ecdsa.VerifyASN1(pub, digest, sig)
			slog.Debug("VerifySignature", "validSig", validSig)
			if !validSig {
				return fmt.Errorf("(VerifySignature) Invalid ECDSA signature")
			}

			return nil
		}
	/*
	* RSA-Encryption
	 */
	case
		oid.OidRsaEncryption.String(),
		oid.OidSha1WithRsaEncryption.String(),
		oid.OidSha224WithRSAEncryption.String(),
		oid.OidSha256WithRSAEncryption.String(),
		oid.OidSha384WithRSAEncryption.String(),
		oid.OidSha512WithRSAEncryption.String():
		{
			var pubKey *cryptoutils.RsaPublicKey
			{
				var subPubKeyInfo SubjectPublicKeyInfo = Asn1decodeSubjectPublicKeyInfo(pubKeyInfo)
				pubKey = subPubKeyInfo.GetRsaPubKey()
			}

			sigPlaintext := cryptoutils.RsaDecryptWithPublicKey(sig, *pubKey)

			slog.Debug("VerifySignature", "sig", utils.BytesToHex(sig), "sigPlaintext", utils.BytesToHex(sigPlaintext))

			// verify the 'RSA Encryption' signature (i.e. the decrypted signature ends with the digest)
			// https://cryptobook.nakov.com/digital-signatures/rsa-signatures
			if !bytes.HasSuffix(sigPlaintext, digest) {
				slog.Debug("VerifySignature - RSA Signature verification FAILED")
				return fmt.Errorf("(VerifySignature) Invalid RSA signature")
			}

			return nil
		}
	/*
	* RSA-PSS
	 */
	case oid.OidRsaSsaPss.String():
		{
			var rsaPubKey *rsa.PublicKey
			{
				var subPubKeyInfo SubjectPublicKeyInfo = Asn1decodeSubjectPublicKeyInfo(pubKeyInfo)
				var pubKey *cryptoutils.RsaPublicKey = subPubKeyInfo.GetRsaPubKey()
				rsaPubKey = &rsa.PublicKey{N: pubKey.N, E: pubKey.E}
			}

			err = rsa.VerifyPSS(rsaPubKey, cryptoutils.CryptoHashOidToAlg(digestAlg), digest, sig, nil)
			if err != nil {
				return fmt.Errorf("(VerifySignature) Invalid PSS signature: %w", err)
			}

			return nil
		}
	default:
		return fmt.Errorf("(VerifySignature) signature-algorithm not supported: %s", sigAlg.String())
	}

	return fmt.Errorf("(VerifySignature) unhandled error")
}

func asn1decodeOid(data []byte) asn1.ObjectIdentifier {
	var out asn1.ObjectIdentifier
	err := utils.ParseAsn1(data, false, &out)
	if err != nil {
		log.Panicf("(asn1decodeOid) Unexpected ASN1 parsing error: %s", err)
	}
	return out
}

func asn1decodeBytes(data []byte) []byte {
	var out []byte
	err := utils.ParseAsn1(data, false, &out)
	if err != nil {
		log.Panicf("(asn1decodeBytes) Unexpected ASN1 parsing error: %s", err)
	}
	return out
}

func Asn1decodeSubjectPublicKeyInfo(data []byte) SubjectPublicKeyInfo {
	var out SubjectPublicKeyInfo
	err := utils.ParseAsn1(data, false, &out)
	if err != nil {
		log.Panicf("(asn1decodeSubjectPublicKeyInfo) Unexpected ASN1 parsing error: %s", err)
	}
	return out
}

func (subPubKeyInfo *SubjectPublicKeyInfo) GetEcCurveAndPubKey() (curve *elliptic.Curve, pubKey *cryptoutils.EcPoint) {
	/*
	* Note: We avoid using 'ParsePKIXPublicKey' as it follows PKIX standard and only allows names curves,
	*       but passports tends to use specified curves (i.e. curve parameters, even if corresponding to well-known curves)
	 */

	var err error

	// verify Algorithm OID
	{
		var expOid asn1.ObjectIdentifier = oid.OidEcPublicKey
		if !subPubKeyInfo.Algorithm.Algorithm.Equal(expOid) {
			log.Panicf("(SubjectPublicKeyInfo.GetEcCurveAndPubKey) Algorithm differs to expected (exp:%s) (act:%s)", expOid.String(), subPubKeyInfo.Algorithm.Algorithm.String())
		}
	}

	var specDomain *ECSpecifiedDomain
	specDomain, err = ParseECSpecifiedDomain(&subPubKeyInfo.Algorithm)
	if err == nil {
		curve, err = specDomain.GetEcCurve()
		if err != nil {
			log.Panicf("(SubjectPublicKeyInfo.GetEcCurveAndPubKey) GetECCurveForSpecifiedDomain error: %s", err)
		}
	} else {
		/*
		* may be 'named curve'...
		 */
		err = nil

		var tmpOid asn1.ObjectIdentifier

		err = utils.ParseAsn1(subPubKeyInfo.Algorithm.Parameters.FullBytes, false, &tmpOid)
		if err != nil {
			log.Panicf("(SubjectPublicKeyInfo.GetEcCurveAndPubKey) Unable to parse EC Params (%x)", subPubKeyInfo.Algorithm.Parameters.FullBytes)
		}

		// TODO - use lookup.. and add support for the wider range of named curves...
		//			- at present we've only observed P384 in the master-list(DE)
		if tmpOid.Equal(oid.OidSecp384r1) {
			var tmpCurve elliptic.Curve = elliptic.P384()
			curve = &tmpCurve
		} else {
			// unsupported named curve
			log.Panicf("Unsupported EC Named Curve (OID:%s)", tmpOid.String())
		}
	}

	// get the chip's public key
	{
		var chipPubKeyBytes []byte = subPubKeyInfo.SubjectPublicKey.Bytes
		pubKey = cryptoutils.DecodeX962EcPoint(*curve, chipPubKeyBytes)
	}

	return curve, pubKey
}

func (subPubKeyInfo *SubjectPublicKeyInfo) GetRsaPubKey() *cryptoutils.RsaPublicKey {
	var err error
	var out cryptoutils.RsaPublicKey

	// verify Algorithm OID
	{
		var expOid asn1.ObjectIdentifier = oid.OidRsaEncryption
		if !subPubKeyInfo.Algorithm.Algorithm.Equal(expOid) {
			log.Panicf("(SubjectPublicKeyInfo.GetRsaPubKey) Algorithm differs to expected (exp:%s) (act:%s)", expOid.String(), subPubKeyInfo.Algorithm.Algorithm.String())
		}
	}

	err = utils.ParseAsn1(subPubKeyInfo.SubjectPublicKey.Bytes, false, &out)
	if err != nil {
		log.Panicf("(SubjectPublicKeyInfo.GetRsaPubKey) Unexpected ASN1 parsing error: %s", err)
	}

	return &out
}

// TODO - looks like this is the inner part of SubjectPublicKeyInfo (used by ActiveAuth/PassiveAuth)
//   - maybe we can generalise this code and use the get function to get the key we require
type ECSpecifiedDomain struct {
	Raw      asn1.RawContent
	Version  int
	FieldId  cryptoutils.ECField
	Curve    cryptoutils.ECCurve
	Base     []byte
	Order    *big.Int
	Cofactor *big.Int
	Hash     asn1.ObjectIdentifier `asn1:"optional"`
}

// parse ecPublicKey ASN1 object (aka EC Specified Domain)
// TODO - this looks like SubjectPublicKeyInfo... also required in SOD... this is just specific to EC.. or at least the curve part of it
func ParseECSpecifiedDomain(algIdentifier *AlgorithmIdentifier) (out *ECSpecifiedDomain, err error) {
	slog.Debug("ParseECSpecifiedDomain", "Algorithm Identifier", algIdentifier)

	if !algIdentifier.Algorithm.Equal(oid.OidEcPublicKey) {
		// TODO - should we panic?
		log.Panicf("expected ecPublicKey OID")
	}

	out = new(ECSpecifiedDomain)

	slog.Debug("ParseECSpecifiedDomain", "Parameters(bytes)", utils.BytesToHex(algIdentifier.Parameters.FullBytes))

	err = utils.ParseAsn1(algIdentifier.Parameters.FullBytes, true, out) // TODO - NB may have extra field after
	if err != nil {
		return nil, fmt.Errorf("(ParseECSpecifiedDomain) ASN1 parsing error: %w", err)
	}

	// TODO - any other data checks?
	if !out.FieldId.FieldType.Equal(oid.OidPrimeField) {
		return nil, fmt.Errorf("(ParseECSpecifiedDomain) PrimeField OID expected")
	}

	slog.Debug("ParseECSpecifiedDomain",
		"Version", out.Version,
		"FieldId.FieldType", out.FieldId.FieldType.String(),
		"FieldId.Parameters", utils.BytesToHex(out.FieldId.Parameters.Bytes),
		"Curve.A", utils.BytesToHex(out.Curve.A),
		"Curve.B", utils.BytesToHex(out.Curve.B),
		"Curve.Seed", utils.BytesToHex(out.Curve.Seed.Bytes),
		"Base", utils.BytesToHex(out.Base),
		"Order", utils.BytesToHex(out.Order.Bytes()),
		"Cofactor", utils.BytesToHex(out.Cofactor.Bytes()),
	)

	return out, nil
}

var ecLookupArr []elliptic.Curve = []elliptic.Curve{
	cryptoutils.EllipticP192(),
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

// Technically we should support 'total' cryptographic agility and allow the MRTD to
// dictate any DH/ECDH parameters of its choosing. However, it's more likely that MRTDs
// are referencing well-known parameters instead of using random (and potentially unsafe)
// settings, so we intentionally support a limited subset and will evaluate this over time.
//
// e.g. if OID = id-ecPublicKey
//
//	then get the curve (as here)
//	and then get/set the public key
//
// SubjectPublicKeyInfo is specified in x509, but basically
//
//	algorithmIdentifier (OID=id-ecPublicKey, params=specifiedDomain)
//	params? public key
//
//	SubjectPublicKeyInfo  ::=  SEQUENCE  {
//	   algorithm            AlgorithmIdentifier,
//	   subjectPublicKey     BIT STRING  }
func (specDomain ECSpecifiedDomain) GetEcCurve() (*elliptic.Curve, error) {

	slog.Debug("GetEcCurve", "Params", utils.BytesToHex(specDomain.FieldId.Parameters.Bytes))

	// look for matching 'standard' curve
	// NB we currently expect the use of standard curve, we may need to support custom curves in the future (but hopefully not)
	for i := 0; i < len(ecLookupArr); i++ {
		var ec elliptic.Curve = ecLookupArr[i]

		// match using the 'prime field' (P)
		// NB normally we skip the 1st byte when matching, but sometimes we do an exact match (e.g. EC521 in DE-master-list cert #361)
		if slices.Equal(ec.Params().P.Bytes(), specDomain.FieldId.Parameters.Bytes[1:]) || // skip 1st byte
			slices.Equal(ec.Params().P.Bytes(), specDomain.FieldId.Parameters.Bytes[0:]) { // don't skip 1st byte
			slog.Debug("GetEcCurve - found curve", "i", i)
			return &ec, nil
		}
	}

	return nil, fmt.Errorf("(ECSpecifiedDomain.GetEcCurve) unsupported CA EC (Params:%x) (Raw:%x)", specDomain.FieldId.Parameters.Bytes, specDomain.Raw)
}

/*
RFC 3447        PKCS #1: RSA Cryptography Specifications   February 2003

RSASSA-PSS-params ::= SEQUENCE {
          hashAlgorithm      [0] HashAlgorithm    DEFAULT sha1,
          maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
          saltLength         [2] INTEGER          DEFAULT 20,
          trailerField       [3] TrailerField     DEFAULT trailerFieldBC
      }
*/

type RsaSsaPssParams struct {
	HashAlgorithm    AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MaskGenAlgorithm AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength       *big.Int            `asn1:"explicit,optional,tag:2"`
	TrailerField     *big.Int            `asn1:"explicit,optional,tag:3"`
}

// Maps signature algorithm OIDs to digest algorithm OIDs
// NB extra processing is required for RSA-PSS, so clients should use AlgorithmIdentifier.DetermineDigestAlgFromSigAlg()
var oidSignatureAlgToDigestAlg = map[string]asn1.ObjectIdentifier{
	oid.OidEcdsaWithSHA1.String():           oid.OidHashAlgorithmSHA1,
	oid.OidEcdsaWithSHA224.String():         oid.OidHashAlgorithmSHA224,
	oid.OidEcdsaWithSHA256.String():         oid.OidHashAlgorithmSHA256,
	oid.OidEcdsaWithSHA384.String():         oid.OidHashAlgorithmSHA384,
	oid.OidEcdsaWithSHA512.String():         oid.OidHashAlgorithmSHA512,
	oid.OidSha1WithRsaEncryption.String():   oid.OidHashAlgorithmSHA1,
	oid.OidSha224WithRSAEncryption.String(): oid.OidHashAlgorithmSHA224,
	oid.OidSha256WithRSAEncryption.String(): oid.OidHashAlgorithmSHA256,
	oid.OidSha384WithRSAEncryption.String(): oid.OidHashAlgorithmSHA384,
	oid.OidSha512WithRSAEncryption.String(): oid.OidHashAlgorithmSHA512,
	// NB RSA-PSS has to be managed separately, so not included here
}

// determines the digest algorithm from the provided signature algorithm
// e.g. OidSha512WithRSAEncryption -> OidHashAlgorithmSHA512
func (signature AlgorithmIdentifier) DetermineDigestAlgFromSigAlg() (*asn1.ObjectIdentifier, error) {
	var digestAlg asn1.ObjectIdentifier

	if signature.Algorithm.Equal(oid.OidRsaSsaPss) {
		/*
		* special handling for RSA-PSS
		 */
		var tmpParams RsaSsaPssParams

		err := utils.ParseAsn1(signature.Parameters.FullBytes, true, &tmpParams)
		if err != nil {
			return nil, fmt.Errorf("(AlgorithmIdentifier.DetermineDigestAlg) error: %s", err)
		}

		digestAlg = tmpParams.HashAlgorithm.Algorithm
	} else {
		/*
		* regular OID lookup for others
		 */
		var ok bool

		digestAlg, ok = oidSignatureAlgToDigestAlg[signature.Algorithm.String()]

		if !ok {
			return nil, fmt.Errorf("(AlgorithmIdentifier.DetermineDigestAlg) unable to resolve digest algorithm from signature algorithm (sig-oid: %s)", signature.Algorithm.String())
		}
	}

	return &digestAlg, nil
}
