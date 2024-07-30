/*
* Cryptographic Message Syntax (CMS) - RFC 5652
* - https://datatracker.ietf.org/doc/html/rfc5652
*
* x509
* - https://datatracker.ietf.org/doc/html/rfc5280
*
* NOTE: bare-bones implementation aimed at supporting MRTD use-cases
 */
package gmrtd

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
)

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
	IssuerAndSerialNumber     IssuerAndSerial     ``
	DigestAlgorithm           AlgorithmIdentifier ``
	AuthenticatedAttributes   AttributeList       `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm AlgorithmIdentifier ``
	EncryptedDigest           []byte              ``
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
	// TODO - can we use the native asn1 encoder to achieve this.. with tags to request explicit tag?
	data = NewTlvSimpleNode(0x31, data).Encode()

	return data
}

type EncapContentInfo struct {
	Raw          asn1.RawContent
	EContentType asn1.ObjectIdentifier ``
	EContent     []byte                `asn1:"explicit,tag:0"` // e.g. LDSSecurityObject / SecurityInfos
}

func parseSignedData(data []byte) (*SignedData, error) {
	var err error
	var signedData SignedData

	err = parseAsn1(data, true, &signedData)
	if err != nil {
		return nil, fmt.Errorf("asn1 parsing error: %s", err)
	}

	// TODO - we're not currently verifying the data... e.g. do we have the correct OIDs

	return &signedData, nil
}

func parseCertificate(data []byte) (*Certificate, error) {
	var err error
	var certificate Certificate

	err = parseAsn1(data, false, &certificate)
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

type TBSCertificate struct {
	Raw                  asn1.RawContent
	Version              int `asn1:"explicit,default:1,tag:0"`
	SerialNumber         int
	Signature            AlgorithmIdentifier
	Issuer               asn1.RawValue
	Validity             Validity
	Subject              asn1.RawValue
	SubjectPublicKeyInfo asn1.RawValue
	IssuerUniqueId       asn1.BitString `asn1:"implicit,optional,tag:1"`
	SubjectUniqueId      asn1.BitString `asn1:"implicit,optional,tag:2"`
	Extensions           []Extension    `asn1:"explicit,optional,tag:3"`
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

// TODO - why return 'bool' and not just 'error'... none of these should fail
func (sd *SignedData2) Verify() (bool, error) {
	slog.Debug("SignedData.Verify")

	// TODO
	/*
		- for each signer-info
			- determine the hash alg (siHashAlg)
			- determine the context type that is hashed (e.g. ldsSecurityObject for SOD)
			- get the data that is hashed
			- verify siHash matches the original data (content)
			- verify other info (?TBC?)										<---------------- TODO (e.g. key-perms, signing-time)
			- cert(chain) validation of the signer-info signature
	*/

	cert, err := parseCertificate(sd.Certificates.Bytes)
	if err != nil {
		return false, fmt.Errorf("(Verify) parseCertificate Error: %w", err)
	}

	slog.Debug("Verify", "SubjectPublicKey", BytesToHex(cert.TbsCertificate.SubjectPublicKeyInfo.FullBytes))

	// for-each signer-info
	// NB we only expect 1, but support >1
	for siIdx := 0; siIdx < len(sd.SignerInfos); siIdx++ {
		var si *SignerInfo = &(sd.SignerInfos[siIdx])

		aaContentType := si.AuthenticatedAttributes.GetByOID(oidContentType)
		aaMessageDigest := si.AuthenticatedAttributes.GetByOID(oidMessageDigest)
		if aaContentType == nil || aaMessageDigest == nil {
			return false, fmt.Errorf("(Verify) Expected Authicated-Attribute(s) missing (Content-Type, Message-Digest)")
		}

		var aaContentTypeOID asn1.ObjectIdentifier = asn1decodeOid(aaContentType.Values.Bytes)
		var aaMessageDigestHash []byte = asn1decodeBytes(aaMessageDigest.Values.Bytes)

		slog.Debug("Verify", "AA Content-Type", aaContentTypeOID.String())
		slog.Debug("Verify", "AA Message-Digest", BytesToHex(aaMessageDigestHash))

		// verify Content OID matches Authenticated-Attribute (Content Type)
		if !aaContentTypeOID.Equal(sd.Content.EContentType) {
			return false, fmt.Errorf("(Verify) Content-Type-OID (%s) differs to Authenticated-Attribute (%s)", sd.Content.EContentType.String(), aaContentTypeOID.String())
		}

		var contentHash []byte = CryptoHashByOid(si.DigestAlgorithm.Algorithm, sd.Content.EContent)
		slog.Debug("Verify", "ContentHash", BytesToHex(contentHash))

		// TODO - different process if auth-attr are NOT present... so maybe this is optional?
		//			- sig input would be slightly different
		//			- most of this only applies if we have auth-attributes present... should check even if not handling today
		//				basically if not present then sig is based on content hash.. if present then based on auth-attr and also
		//				need to check hash in  auth-attr (as per current)
		//
		//	5.4.  Message Digest Calculation Process (RFC5652)
		if !bytes.Equal(contentHash, aaMessageDigestHash) {
			// invalid content hash
			slog.Debug("Verify - invalid content hash", "contentHash", BytesToHex(contentHash), "aaMessageDigestHash", BytesToHex(aaMessageDigestHash))
			return false, nil
		}

		var dataToHash []byte = si.AuthenticatedAttributes.GetSetOfAsnBytes()
		slog.Debug("Verify", "dataToHash", BytesToHex(dataToHash))

		digestAlg := si.DigestAlgorithm.Algorithm
		var digest []byte = CryptoHashByOid(digestAlg, dataToHash)
		slog.Debug("Verify", "digest", BytesToHex(digest))

		/*
		* Verify the SignedInfo signature (against the PublicKey in the Certificate)
		 */

		validSig, err := verifySignature(cert.TbsCertificate.SubjectPublicKeyInfo.FullBytes, digestAlg, digest, si.DigestEncryptionAlgorithm.Algorithm, si.EncryptedDigest)
		if err != nil {
			return false, fmt.Errorf("(Verify) verifySignature error: %w", err)
		}
		if !validSig {
			// invalid signature
			slog.Debug("Verify - invalid signature")
			return false, nil
		}

		// TODO - verify the cert/chain... so far we've just verified the signedData and enveloped-data
		//		- we haven't actually verified that the certificate is signed by someone we trust
	}

	return true, nil
}

func verifySignature(pubKeyInfo []byte, digestAlg asn1.ObjectIdentifier, digest []byte, sigAlg asn1.ObjectIdentifier, sig []byte) (bool, error) {
	var err error

	slog.Debug("verifySignature", "pubKeyInfo", BytesToHex(pubKeyInfo), "digestAlg", digestAlg.String(), "digest", BytesToHex(digest), "sigAlg", sigAlg.String(), "sig", BytesToHex(sig))

	switch sigAlg.String() {
	/*
	* ECDSA
	 */
	case
		oidEcdsaWithSHA1.String(),
		oidEcdsaWithSHA224.String(),
		oidEcdsaWithSHA256.String(),
		oidEcdsaWithSHA384.String(),
		oidEcdsaWithSHA512.String():
		{
			// TODO - could check that sig-hash(derived-from-oid) matches original hash (or 'digest' size)
			//			- need to pass in digestAlg for PSS.. so could verify sig-alg is compatible

			var pub *ecdsa.PublicKey
			{
				var subPubKeyInfo SubjectPublicKeyInfo = asn1decodeSubjectPublicKeyInfo(pubKeyInfo)

				var ecCurve *elliptic.Curve
				var ecPoint *EcPoint
				ecCurve, ecPoint = subPubKeyInfo.GetEcCurveAndPubKey()

				pub = &ecdsa.PublicKey{Curve: *ecCurve, X: ecPoint.x, Y: ecPoint.y}
			}

			// VerifyASN1: works with non-nist curves (i.e. brainpool) via legacy code (hopefully this doesn't change)
			validSig := ecdsa.VerifyASN1(pub, digest, sig)
			slog.Debug("verifySignature", "validSig", validSig)
			if validSig {
				return true, nil
			}
		}
	/*
	* RSA-Encryption
	 */
	case oidRsaEncryption.String():
		{
			var rsaPubKey *rsa.PublicKey
			{
				var subPubKeyInfo SubjectPublicKeyInfo = asn1decodeSubjectPublicKeyInfo(pubKeyInfo)
				var pubKey *RsaPublicKey = subPubKeyInfo.GetRsaPubKey()
				rsaPubKey = &rsa.PublicKey{N: pubKey.N, E: pubKey.E}
			}

			sigPlaintext := rsaDecryptWithPublicKey(sig, rsaPubKey)

			slog.Debug("verifySignature", "sig", BytesToHex(sig), "sigPlaintext", BytesToHex(sigPlaintext))

			// verify the 'RSA Encryption' signature (i.e. the decrypted signature ends with the digest)
			// https://cryptobook.nakov.com/digital-signatures/rsa-signatures
			if !bytes.HasSuffix(sigPlaintext, digest) {
				slog.Debug("verifySignature - RSA Signature verification FAILED")
				return false, nil
			}

			return true, nil
		}
	/*
	* RSA-PSS
	 */
	case oidRsaSsaPss.String():
		{
			//log.Printf("rsaPss.. key... %x\n%s\n", pubKeyInfo, TlvDecode(pubKeyInfo).String())

			var rsaPubKey *rsa.PublicKey
			{
				var subPubKeyInfo SubjectPublicKeyInfo = asn1decodeSubjectPublicKeyInfo(pubKeyInfo)
				var pubKey *RsaPublicKey = subPubKeyInfo.GetRsaPubKey()
				rsaPubKey = &rsa.PublicKey{N: pubKey.N, E: pubKey.E}
			}

			err = rsa.VerifyPSS(rsaPubKey, CryptoHashOidToAlg(digestAlg), digest, sig, nil)
			if err != nil {
				return false, fmt.Errorf("(verifySignature) rsa.verifyPSS error: %w", err)
			}
			// TODO - should we catch the error to return clear false,nil? for others qwe return 'false'.. here we're just getting error
			//	e.g. sod_test.go:117: Error verifying SignedData: (Verify) verifySignature error: (verifySignature) rsa.verifyPSS error: crypto/rsa: verification error
			//			- crypto/rsa: verification error (rsa.ErrVerification ?)

			return true, nil
		}
	default:
		return false, fmt.Errorf("(verifySignature) signature-algorithm not supported: %s", sigAlg.String())
	}

	return false, fmt.Errorf("(verifySignature) unhandled error")
}

func asn1decodeOid(data []byte) asn1.ObjectIdentifier {
	var out asn1.ObjectIdentifier
	err := parseAsn1(data, false, &out)
	if err != nil {
		log.Panicf("(asn1decodeOid) Unexpected ASN1 parsing error: %s", err)
	}
	return out
}

func asn1decodeBytes(data []byte) []byte {
	var out []byte
	err := parseAsn1(data, false, &out)
	if err != nil {
		log.Panicf("(asn1decodeBytes) Unexpected ASN1 parsing error: %s", err)
	}
	return out
}

func asn1decodeSubjectPublicKeyInfo(data []byte) SubjectPublicKeyInfo {
	var out SubjectPublicKeyInfo
	err := parseAsn1(data, false, &out)
	if err != nil {
		log.Panicf("(asn1decodeSubjectPublicKeyInfo) Unexpected ASN1 parsing error: %s", err)
	}
	return out
}
