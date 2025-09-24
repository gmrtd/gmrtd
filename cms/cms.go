// Package cms implements the 'Cryptographic Message Syntax' (CMS) as described in RFC-5652.
//
// Support is also provided for X509 (RFC-5652)
//
// This package provides basic support for CMS/X509 to support MRTD use-cases.
//
// Notes:
// - Revocation checks not supported
package cms

/*
* references:
*
* NIST example for ECDSA:
* https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/P521_SHA512.pdf
*
* test vectors:
* https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_brainpoolP256r1_sha256_test.json
 */

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/json"
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

type SubjectPublicKeyInfo struct {
	Algorithm        AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func (spk SubjectPublicKeyInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Algorithm        AlgorithmIdentifier `json:"algorithm,omitempty"`
		SubjectPublicKey []byte              `json:"subjectPublicKey,omitempty"`
	}{
		Algorithm:        spk.Algorithm,
		SubjectPublicKey: spk.SubjectPublicKey.Bytes,
	})
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

func (ai AlgorithmIdentifier) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Algorithm  string `json:"algorithm,omitempty"`
		Parameters []byte `json:"parameters,omitempty"`
	}{
		Algorithm:  ai.Algorithm.String(),
		Parameters: ai.Parameters.FullBytes,
	})
}

type ContentInfo struct {
	Type    asn1.ObjectIdentifier `json:"type"`
	Content asn1.RawValue         `asn1:"explicit,tag:0" json:"content"`
}

type SignedData struct {
	Raw              asn1.RawContent       `json:"raw"`
	Version          int                   `json:"version"`
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set" json:"digestAlgorithms"`
	Content          EncapContentInfo      `json:"content"`
	Certificates     asn1.RawValue         `asn1:"optional,tag:0" json:"certificates"`
	CRLs             []asn1.RawValue       `asn1:"optional,set,tag:1" json:"crls"`
	SignerInfos      []SignerInfo          `asn1:"set" json:"signerInfos"`
}

type SignerInfo struct {
	Raw                       asn1.RawContent     `json:"raw"`
	Version                   int                 `asn1:"default:1" json:"version"`
	Sid                       asn1.RawValue       `json:"sid"`
	DigestAlgorithm           AlgorithmIdentifier `json:"digestAlgorithm"`
	AuthenticatedAttributes   AttributeList       `asn1:"optional,tag:0" json:"authenticatedAttributes"`
	DigestEncryptionAlgorithm AlgorithmIdentifier `json:"digestEncryptionAlgorithm"`
	EncryptedDigest           []byte              `json:"encryptedDigest"`
	UnauthenticatedAttributes AttributeList       `asn1:"optional,tag:1" json:"unauthenticatedAttributes"`
}

// SignerIdentifier ::= CHOICE {
// issuerAndSerialNumber IssuerAndSerialNumber,
// subjectKeyIdentifier [0] SubjectKeyIdentifier }
/*
type IssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}
*/

type Attribute struct {
	Raw    asn1.RawContent
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}
type AttributeList []Attribute

func (a Attribute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   string `json:"type,omitempty"`
		Values []byte `json:"values,omitempty"`
	}{
		Type:   a.Type.String(),
		Values: a.Values.Bytes,
	})
}

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

	for i := range attributes {
		data = append(data, attributes[i].Raw...)
	}

	// wrap with explicit 'SET OF' (0x31) tag
	data = tlv.NewTlvSimpleNode(0x31, data).Encode()

	return data
}

type EncapContentInfo struct {
	Raw          asn1.RawContent       `json:"raw"`
	EContentType asn1.ObjectIdentifier `json:"eContentType"`
	EContent     []byte                `asn1:"explicit,tag:0" json:"eContent"` // e.g. LDSSecurityObject / SecurityInfos
}

func ParseSignedData(data []byte) (*SignedData, error) {
	var err error
	var contentInfo ContentInfo

	err = utils.ParseAsn1(data, false, &contentInfo)
	if err != nil {
		return nil, fmt.Errorf("[ParseSignedData] asn1 parsing error (contentInfo): %s", err)
	}

	// verify we got the expected OID
	if !contentInfo.Type.Equal(oid.OidSignedData) {
		return nil, fmt.Errorf("[ParseSignedData] invalid OID (exp:%s, act:%s)", oid.OidSignedData.String(), contentInfo.Type.String())
	}

	var signedData SignedData

	err = utils.ParseAsn1(contentInfo.Content.Bytes, false, &signedData)
	if err != nil {
		return nil, fmt.Errorf("[ParseSignedData] asn1 parsing error (signedData): %s", err)
	}

	return &signedData, nil
}

func ParseCertificates(data []byte) (certs []Certificate, err error) {
	certs = []Certificate{}

	var remainingData []byte = data

	for len(remainingData) > 0 {
		var tmpCert Certificate

		tmpData, err := utils.ParseAsn1Ex(remainingData, &tmpCert)
		if err != nil {
			return nil, fmt.Errorf("[ParseCertificates] asn1 parsing error: %s", err)
		}

		certs = append(certs, tmpCert)

		remainingData = tmpData
	}

	return certs, nil
}

type Certificate struct {
	Raw                asn1.RawContent     `json:"raw"`
	TbsCertificate     TBSCertificate      `json:"tbsCertificate"`
	SignatureAlgorithm AlgorithmIdentifier `json:"signatureAlgorithm"`
	SignatureValue     asn1.BitString      `json:"signatureValue"`
}

type Extensions []Extension

type AuthorityKeyIdentifier struct {
	KeyIdentifier             []byte          `asn1:"optional,implicit,tag:0" json:"keyIdentifier"`
	AuthorityCertIssuer       asn1.RawContent `asn1:"optional,implicit,tag:1" json:"authorityCertIssuer"`
	AuthorityCertSerialNumber asn1.RawContent `asn1:"optional,implicit,tag:2" json:"authorityCertSerialNumber"`
}

type SubjectKeyIdentifier []byte

func (extensions Extensions) GetAuthorityKeyIdentifier() *AuthorityKeyIdentifier {
	for i := range extensions {
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
	for i := range extensions {
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

type RDNSequence []RelativeDistinguishedNameSET
type RelativeDistinguishedNameSET AttributeList

func ParseRDNSequence(rdnSeq []byte) RDNSequence {
	var out RDNSequence

	err := utils.ParseAsn1(rdnSeq, false, &out)
	if err != nil {
		log.Panicf("ParseRDNSequence error: %s", err)
	}

	return out
}

func (rdnSet RDNSequence) GetByOID(oid asn1.ObjectIdentifier) []byte {
	for _, set := range rdnSet {
		for _, atv := range set {
			if atv.Type.Equal(oid) {
				return bytes.Clone(atv.Values.Bytes)
			}
		}
	}

	return []byte{}
}

func (cert TBSCertificate) GetIssuerRDN() RDNSequence {
	return ParseRDNSequence(cert.Issuer.FullBytes)
}

type TBSCertificate struct {
	Raw                  asn1.RawContent     `json:"raw"`
	Version              int                 `asn1:"explicit,default:1,tag:0" json:"version"`
	SerialNumber         *big.Int            `json:"serialNumber"`
	Signature            AlgorithmIdentifier `json:"signature"`
	Issuer               asn1.RawValue       `json:"issuer"`
	Validity             Validity            `json:"validity"`
	Subject              asn1.RawValue       `json:"subject"`
	SubjectPublicKeyInfo asn1.RawValue       `json:"subjectPublicKeyInfo"`
	IssuerUniqueId       asn1.BitString      `asn1:"implicit,optional,tag:1" json:"issuerUniqueId"`
	SubjectUniqueId      asn1.BitString      `asn1:"implicit,optional,tag:2" json:"subjectUniqueId"`
	Extensions           Extensions          `asn1:"explicit,optional,tag:3" json:"extensions"`
}

type Validity struct {
	NotBefore asn1.RawValue `json:"notBefore"`
	NotAfter  asn1.RawValue `json:"notAfter"`
}

type Extension struct {
	Raw       asn1.RawContent       `json:"raw"`
	ObjectId  asn1.ObjectIdentifier `json:"objectId"`
	Critical  asn1.Flag             `asn1:"optional,default:false" json:"critical"`
	ExtnValue asn1.RawValue         `json:"extnValue"`
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

func (si *SignerInfo) Verify(sd *SignedData, trustedCerts CertPool) (certChain [][]byte, err error) {
	var dataToHash []byte
	var digestAlg *asn1.ObjectIdentifier
	var signatureAlg *asn1.ObjectIdentifier
	var signature []byte

	/*
		- for each signer-info
			- determine the hash alg (siHashAlg)
			- determine the context type that is hashed (e.g. ldsSecurityObject for SOD)
			- get the data that is hashed
			- verify siHash matches the original data (content)
			- verify other info (?TBC?)										<---------------- TODO (e.g. key-perms, signing-time)
			- cert(chain) validation of the signer-info signature
	*/

	/*
	* proceed based on whether or not 'authenticated attributes' are present
	 */
	if len(si.AuthenticatedAttributes) < 1 {
		return nil, fmt.Errorf("[Verify] SignedInfo without AuthenticatedAttributes is NOT supported")
	} else {
		aaContentType := si.AuthenticatedAttributes.GetByOID(oid.OidContentType)
		aaMessageDigest := si.AuthenticatedAttributes.GetByOID(oid.OidMessageDigest)
		if aaContentType == nil || aaMessageDigest == nil {
			return nil, fmt.Errorf("[Verify] Expected Authenticated-Attribute(s) missing (Content-Type, Message-Digest) %v", si)
		}

		var aaContentTypeOID asn1.ObjectIdentifier = asn1decodeOid(aaContentType.Values.Bytes)
		var aaMessageDigestHash []byte = asn1decodeBytes(aaMessageDigest.Values.Bytes)

		slog.Debug("Verify", "AA Content-Type", aaContentTypeOID.String())
		slog.Debug("Verify", "AA Message-Digest", utils.BytesToHex(aaMessageDigestHash))

		// verify Content OID matches Authenticated-Attribute (Content Type)
		if !aaContentTypeOID.Equal(sd.Content.EContentType) {
			return nil, fmt.Errorf("[Verify] Content-Type-OID (%s) differs to Authenticated-Attribute (%s)", sd.Content.EContentType.String(), aaContentTypeOID.String())
		}

		var contentHash []byte
		contentHash, err = cryptoutils.CryptoHashByOid(si.DigestAlgorithm.Algorithm, sd.Content.EContent)
		if err != nil {
			return nil, fmt.Errorf("[Verify] CryptoHashByOid error: %w", err)
		}

		slog.Debug("Verify", "ContentHash", utils.BytesToHex(contentHash))

		//	5.4.  Message Digest Calculation Process (RFC5652)
		if !bytes.Equal(contentHash, aaMessageDigestHash) {
			// invalid content hash
			slog.Debug("Verify - invalid content hash", "contentHash", utils.BytesToHex(contentHash), "aaMessageDigestHash", utils.BytesToHex(aaMessageDigestHash))
			return nil, fmt.Errorf("[Verify] Invalid content hash (contentHash:%x, aaMessageDigestHash:%x)", contentHash, aaMessageDigestHash)
		}

		dataToHash = si.AuthenticatedAttributes.GetSetOfAsnBytes()

		digestAlg = &(si.DigestAlgorithm.Algorithm)

		signatureAlg = &(si.DigestEncryptionAlgorithm.Algorithm)
		signature = si.EncryptedDigest
	}

	var digest []byte
	digest, err = cryptoutils.CryptoHashByOid(*digestAlg, dataToHash)
	if err != nil {
		return nil, fmt.Errorf("[Verify] CryptoHashByOid error: %w", err)
	}

	slog.Debug("Verify", "digestAlg", digestAlg.String(), "digest", utils.BytesToHex(digest))

	/*
	* Select certificate from signed-data
	 */
	var cert *Certificate
	{
		var sdCerts *GenericCertPool = &GenericCertPool{}

		err = sdCerts.Add(sd.Certificates.Bytes)
		if err != nil {
			return nil, fmt.Errorf("[Verify] CertPool.Add error: %w", err)
		}

		var tmpCerts []Certificate

		if sdCerts.Count() == 1 {
			// if we only have 1 certificate in the signed-data then we'll just use that
			tmpCerts = append(tmpCerts, sdCerts.certificates...)
		} else if sdCerts.Count() > 1 {
			// pick the certificate(s) if multiple exist
			// TODO - should support other variants also (e.g. issuer+serialNumber).. sid is not always aki
			tmpCerts = sdCerts.GetBySKI(si.Sid.Bytes)
		}

		if len(tmpCerts) != 1 {
			return nil, fmt.Errorf("[Verify] Expected a single matching Cert from within the SignedData (got:%d) (sid:%x)", len(tmpCerts), si.Sid.FullBytes)
		}

		cert = &tmpCerts[0]
	}

	/*
	* Verify the SignedInfo signature (against the PublicKey in the Certificate)
	 */
	err = VerifySignature(cert.TbsCertificate.SubjectPublicKeyInfo.FullBytes, *digestAlg, digest, *signatureAlg, signature)
	if err != nil {
		return nil, fmt.Errorf("[Verify] VerifySignature error: %w", err)
	}

	// record the 'initial' certificate
	certChain = append(certChain, bytes.Clone(cert.Raw))

	/*
	* verify the cert/chain
	* so far we've just verified the signedData and enveloped-data we haven't actually verified that the certificate is signed by someone we trust
	 */
	{
		tmpCertChain, err := cert.Verify(trustedCerts)
		if err != nil {
			return nil, fmt.Errorf("[Verify] cert.Verify error: %w", err)
		}

		// record the certificate(s) used during verification
		certChain = append(certChain, tmpCertChain...)
	}

	return certChain, nil
}

func (sd *SignedData) Verify(trustedCerts CertPool) (certChain [][]byte, err error) {
	slog.Debug("SignedData.Verify")

	slog.Debug("Verify", "SignerInfo(cnt)", len(sd.SignerInfos))

	// check that we have some SignedInfos
	if len(sd.SignerInfos) < 1 {
		return nil, fmt.Errorf("[Verify] NO SignerInfos present")
	}

	// for-each signer-info
	for siIdx := range sd.SignerInfos {
		var tmpCertChain [][]byte

		tmpCertChain, err = sd.SignerInfos[siIdx].Verify(sd, trustedCerts)
		if err != nil {
			return nil, fmt.Errorf("[Verify] si.Verify(idx:%d) error: %w", siIdx, err)
		}

		certChain = append(certChain, tmpCertChain...)
	}

	return certChain, nil
}

// verifies that the certificate was signed by one of the certificates in 'trustedCerts'
// NB considers all entries in 'trustedCerts' to be valid signers, so doesn't walk the chain to a root-cert
func (cert *Certificate) Verify(trustedCerts CertPool) (certChain [][]byte, err error) {
	// TODO - currently just verifies the signature... doesn't check anything else... e.g. signing-time-validity...
	//			see 9303p10 5.1 Passive Authentication for detailed overview
	// - for MRTD, country is indirectly validated by passive-auth as it will only provide 'trustedCerts' for the country based on the MRZ

	slog.Debug("CERT.Verify", "Cert(hex)", utils.BytesToHex(cert.Raw))

	// get the parent certificate (authority) key identifier
	var aki *AuthorityKeyIdentifier = cert.TbsCertificate.Extensions.GetAuthorityKeyIdentifier()
	if aki == nil {
		return certChain, fmt.Errorf("[Certificate.Verify] AKI missing from cert (%x)", cert.Raw)
	}

	// determine the digest-alg for the cert
	var certDigestAlg *asn1.ObjectIdentifier
	certDigestAlg, err = cert.SignatureAlgorithm.DetermineDigestAlgFromSigAlg()
	if err != nil {
		return certChain, fmt.Errorf("[Certificate.Verify] unable to determine digest-alg from signature-alg: %w", err)
	}

	// calculate the cert digest
	var certDigest []byte
	certDigest, err = cryptoutils.CryptoHashByOid(*certDigestAlg, cert.TbsCertificate.Raw)
	if err != nil {
		return nil, fmt.Errorf("[Certificate.Verify] CryptoHashByOid error: %w", err)
	}

	// get any matching parent certificates
	// NB often >1 due to cross-signing in master-list
	parentCerts := trustedCerts.GetBySKI(aki.KeyIdentifier) // TODO - other variants? eg issuer/serial

	slog.Debug("Certificate.Verify", "parentCerts(cnt)", len(parentCerts))

	// stop if no parent cert(s) found
	if len(parentCerts) < 1 {
		return certChain, fmt.Errorf("[Certificate.Verify] unable to locate parent certificate (SKI:%x)", aki.KeyIdentifier)
	}

	// test each parent cert until we find one that validates the cert signature
	for i := range parentCerts {
		tmpErr := VerifySignature(parentCerts[i].TbsCertificate.SubjectPublicKeyInfo.FullBytes, *certDigestAlg, certDigest, cert.SignatureAlgorithm.Algorithm, cert.SignatureValue.Bytes)
		if tmpErr != nil {
			// ignore error and try other parent certs
			slog.Debug("Certificate.Verify - skipping parent cert as it failed to verify the signature", "idx", i)
			continue
		}

		// record cert
		certChain = append(certChain, bytes.Clone(parentCerts[i].Raw))

		// TODO - if we wanted to process to official root, the parent cert verification would be here, if parentCert is not CA-Cert

		return certChain, nil
	}

	return certChain, fmt.Errorf("[Certificate.Verify] signature not verified against matched certificates (matchCnt:%d,aki:%x,cert:%x)", len(parentCerts), aki.KeyIdentifier, cert.Raw)
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

type EcNamedCurve struct {
	oid   asn1.ObjectIdentifier `json:"oid"`
	curve elliptic.Curve        `json:"curve"`
}

var ecNamedCurveArr []EcNamedCurve = []EcNamedCurve{
	{oid: oid.OidPrime192v1, curve: cryptoutils.EllipticP192()},
	{oid: oid.OidSecp224r1, curve: elliptic.P224()},
	{oid: oid.OidPrime256v1, curve: elliptic.P256()},
	{oid: oid.OidSecp384r1, curve: elliptic.P384()},
	{oid: oid.OidSecp521r1, curve: elliptic.P521()},
	{oid: oid.OidBrainpoolP192r1, curve: brainpool.P192r1()},
	{oid: oid.OidBrainpoolP224r1, curve: brainpool.P224r1()},
	{oid: oid.OidBrainpoolP256r1, curve: brainpool.P256r1()},
	{oid: oid.OidBrainpoolP320r1, curve: brainpool.P320r1()},
	{oid: oid.OidBrainpoolP384r1, curve: brainpool.P384r1()},
	{oid: oid.OidBrainpoolP512r1, curve: brainpool.P512r1()},
}

func (subPubKeyInfo *SubjectPublicKeyInfo) GetEcCurveAndPubKey() (curve *elliptic.Curve, pubKey *cryptoutils.EcPoint, err error) {
	/*
	* Note: We avoid using 'ParsePKIXPublicKey' as it follows PKIX standard and only allows names curves,
	*       but passports tend to use specified curves (i.e. curve parameters, even if corresponding to well-known curves)
	 */

	// verify Algorithm OID
	{
		var expOid asn1.ObjectIdentifier = oid.OidEcPublicKey
		if !subPubKeyInfo.Algorithm.Algorithm.Equal(expOid) {
			return nil, nil, fmt.Errorf("[GetEcCurveAndPubKey] Algorithm differs to expected (exp:%s) (act:%s)", expOid.String(), subPubKeyInfo.Algorithm.Algorithm.String())
		}
	}

	var specDomain *ECSpecifiedDomain
	specDomain, err = ParseECSpecifiedDomain(&subPubKeyInfo.Algorithm)
	if err == nil {
		curve, err = specDomain.GetEcCurve()
		if err != nil {
			return nil, nil, fmt.Errorf("[GetEcCurveAndPubKey] GetEcCurve error: %w", err)
		}
	} else {
		/*
		* may be 'named curve'...
		 */
		var tmpOid asn1.ObjectIdentifier

		err = utils.ParseAsn1(subPubKeyInfo.Algorithm.Parameters.FullBytes, false, &tmpOid)
		if err != nil {
			return nil, nil, fmt.Errorf("[GetEcCurveAndPubKey] ParseAsn1 error: %w", err)
		}

		for i := range ecNamedCurveArr {
			if ecNamedCurveArr[i].oid.Equal(tmpOid) {
				// found
				curve = &(ecNamedCurveArr[i].curve)
				break
			}
		}

		if curve == nil {
			// unsupported named curve
			return nil, nil, fmt.Errorf("[GetEcCurveAndPubKey] Unsupported EC Named Curve (OID:%s)", tmpOid.String())
		}
	}

	// get the chip's public key
	{
		var chipPubKeyBytes []byte = subPubKeyInfo.SubjectPublicKey.Bytes
		pubKey = cryptoutils.DecodeX962EcPoint(*curve, chipPubKeyBytes)
	}

	return curve, pubKey, nil
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

type ECSpecifiedDomain struct {
	Raw      asn1.RawContent       `json:"raw"`
	Version  int                   `json:"version"`
	FieldId  cryptoutils.ECField   `json:"fieldId"`
	Curve    cryptoutils.ECCurve   `json:"curve"`
	Base     []byte                `json:"base"`
	Order    *big.Int              `json:"order"`
	Cofactor *big.Int              `json:"cofactor"`
	Hash     asn1.ObjectIdentifier `asn1:"optional" json:"hash"`
}

// parse ecPublicKey ASN1 object (aka EC Specified Domain)
func ParseECSpecifiedDomain(algIdentifier *AlgorithmIdentifier) (out *ECSpecifiedDomain, err error) {
	slog.Debug("ParseECSpecifiedDomain", "Algorithm Identifier", algIdentifier)

	if !algIdentifier.Algorithm.Equal(oid.OidEcPublicKey) {
		return nil, fmt.Errorf("(ParseECSpecifiedDomain) expected ecPublicKey OID (exp:%s, act:%s)", oid.OidEcPublicKey.String(), algIdentifier.Algorithm.String())
	}

	out = new(ECSpecifiedDomain)

	slog.Debug("ParseECSpecifiedDomain", "Parameters(bytes)", utils.BytesToHex(algIdentifier.Parameters.FullBytes))

	err = utils.ParseAsn1(algIdentifier.Parameters.FullBytes, true, out) // NB may have extra field after
	if err != nil {
		return nil, fmt.Errorf("(ParseECSpecifiedDomain) ASN1 parsing error: %w", err)
	}

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

	// NB sometimes there can be leading zero
	specDomainPBytes := utils.TrimLeadingZeroBytes(specDomain.FieldId.Parameters.Bytes)

	// look for matching 'standard' curve
	// NB we currently expect the use of standard curve, we may need to support custom curves in the future (but hopefully not)
	for i := 0; i < len(ecLookupArr); i++ {
		var ec elliptic.Curve = ecLookupArr[i]

		// match using the 'prime field' (P)
		if slices.Equal(ec.Params().P.Bytes(), specDomainPBytes) {
			slog.Debug("GetEcCurve", "curveIdx", i, "specDomain", specDomain)
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
	HashAlgorithm    AlgorithmIdentifier `asn1:"explicit,tag:0" json:"hashAlgorithm"`
	MaskGenAlgorithm AlgorithmIdentifier `asn1:"explicit,tag:1" json:"maskGenAlgorithm"`
	SaltLength       *big.Int            `asn1:"explicit,optional,tag:2" json:"saltLength"`
	TrailerField     *big.Int            `asn1:"explicit,optional,tag:3" json:"trailerField"`
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

		err := utils.ParseAsn1(signature.Parameters.FullBytes, false, &tmpParams)
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
