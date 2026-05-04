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
	"log/slog"
	"math/big"
	"slices"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
	"github.com/osanderson/brainpool"
)

// Interfaces for testability
type CryptoHasher interface {
	CryptoHashByOid(oid asn1.ObjectIdentifier, data []byte) ([]byte, error)
}

type Asn1Parser interface {
	ParseAsn1(data []byte, allowExtraData bool, v interface{}) error
}

type CurveLookup interface {
	GetNamedCurves() []EcNamedCurve
	GetLookupCurves() []elliptic.Curve
}

// Default implementations
type DefaultCryptoHasher struct{}

func (d DefaultCryptoHasher) CryptoHashByOid(oid asn1.ObjectIdentifier, data []byte) ([]byte, error) {
	return cryptoutils.CryptoHashByOid(oid, data)
}

type DefaultAsn1Parser struct{}

func (d DefaultAsn1Parser) ParseAsn1(data []byte, allowExtraData bool, v interface{}) error {
	rest, err := asn1.Unmarshal(data, v)
	if err != nil {
		return fmt.Errorf("(ParseAsn1) %w", err)
	}

	if !allowExtraData && len(rest) > 0 {
		return fmt.Errorf("unexpected data remaining after ASN1 parsing (Data:%x) (Remaining:%x)", data, rest)
	}

	return nil
}

type DefaultCurveLookup struct{}

func (d DefaultCurveLookup) GetNamedCurves() []EcNamedCurve {
	return []EcNamedCurve{
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
}

func (d DefaultCurveLookup) GetLookupCurves() []elliptic.Curve {
	return []elliptic.Curve{
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
}

// CMSConfig holds configurable dependencies for CMS operations
type CMSConfig struct {
	Hasher      CryptoHasher
	Parser      Asn1Parser
	CurveLookup CurveLookup
	SigAlgMap   map[string]asn1.ObjectIdentifier
}

// NewDefaultCMSConfig creates a config with default implementations
func NewDefaultCMSConfig() *CMSConfig {
	return &CMSConfig{
		Hasher:      DefaultCryptoHasher{},
		Parser:      DefaultAsn1Parser{},
		CurveLookup: DefaultCurveLookup{},
		SigAlgMap: map[string]asn1.ObjectIdentifier{
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
		},
	}
}

// TODO - review and ensure that instances of asn1.ObjectIdentifier have MarshalJSON to string notation

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
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,tag:0"`
}

func (ci ContentInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type    string `json:"type,omitempty"`
		Content []byte `json:"content,omitempty"`
	}{
		Type:    ci.Type.String(),
		Content: ci.Content.FullBytes,
	})
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

// TODO - MarshalJSON

type SignerInfo struct {
	Raw                       asn1.RawContent     `json:"raw"`
	Version                   int                 `asn1:"default:1" json:"version"`
	Sid                       asn1.RawValue       `json:"sid"`
	DigestAlgorithm           AlgorithmIdentifier `json:"digestAlgorithm"`
	AuthenticatedAttributes   AttributeList       `asn1:"optional,tag:0" json:"authenticatedAttributes,omitempty"`
	DigestEncryptionAlgorithm AlgorithmIdentifier `json:"digestEncryptionAlgorithm"`
	EncryptedDigest           []byte              `json:"encryptedDigest"`
	UnauthenticatedAttributes AttributeList       `asn1:"optional,tag:1" json:"unauthenticatedAttributes,omitempty"`
}

// TODO - MarshalJSON

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

func (a Attribute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   string `json:"type,omitempty"`
		Values []byte `json:"values,omitempty"`
	}{
		Type:   a.Type.String(),
		Values: a.Values.FullBytes,
	})
}

type AttributeList []Attribute

// returns: nil if no matching attribute found
func (attributes AttributeList) ByOID(oid asn1.ObjectIdentifier) *Attribute {
	for i := 0; i < len(attributes); i++ {
		if oid.Equal(attributes[i].Type) {
			return &(attributes[i])
		}
	}

	return nil
}

// gets the ASN1 encoded attribute data wrapped in a parent 'SET OF' (0x31) tag
// NB builds using the 'Raw' field, so any changes to the low-level fields will not be reflected
func (attributes AttributeList) SetOfAsnBytes() []byte {
	// A separate encoding
	// of the signedAttrs field is performed for message digest calculation.
	// The IMPLICIT [0] tag in the signedAttrs is not used for the DER
	// encoding, rather an EXPLICIT SET OF tag is used.  That is, the DER
	// encoding of the EXPLICIT SET OF tag, rather than of the IMPLICIT [0]
	// tag, MUST be included in the message digest calculation along with
	// the length and content octets of the SignedAttributes value.
	//
	// https://datatracker.ietf.org/doc/html/rfc5652#section-5.4

	var attributeBytes []byte

	for i := range attributes {
		attributeBytes = append(attributeBytes, attributes[i].Raw...)
	}

	return tlv.NewTlvSimpleNode(0x31, attributeBytes).Encode()
}

type EncapContentInfo struct {
	Raw          asn1.RawContent
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,tag:0"` // e.g. LDSSecurityObject / SecurityInfos
}

func (eci EncapContentInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		EContentType string `json:"eContentType,omitempty"`
		EContent     []byte `json:"eContent,omitempty"`
	}{
		EContentType: eci.EContentType.String(),
		EContent:     eci.EContent,
	})
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

// TODO - MarshalJSON

type Extensions []Extension

type AuthorityKeyIdentifier struct {
	KeyIdentifier             []byte          `asn1:"optional,implicit,tag:0" json:"keyIdentifier"`
	AuthorityCertIssuer       asn1.RawContent `asn1:"optional,implicit,tag:1" json:"authorityCertIssuer"`
	AuthorityCertSerialNumber asn1.RawContent `asn1:"optional,implicit,tag:2" json:"authorityCertSerialNumber"`
}

// TODO - MarshalJSON

type SubjectKeyIdentifier []byte

// AuthorityKeyIdentifier locates and parses the Authority Key Identifier (AKI)
// extension from the Extensions collection.
//
// It iterates through the extensions and returns the first extension whose
// ObjectId matches the Authority Key Identifier OID (oid.OidAuthorityKeyIdentifier).
// The extension value is decoded from ASN.1 into an AuthorityKeyIdentifier struct.
//
// Returns:
//   - *AuthorityKeyIdentifier: the parsed AKI structure if present
//   - error: if ASN.1 decoding fails
//
// If no Authority Key Identifier extension is found, the function returns (nil, nil).
//
// Notes:
//   - The function assumes at most one AKI extension is relevant and returns
//     the first match.
//   - The ExtnValue is expected to be a valid ASN.1-encoded AKI structure.
//   - A nil result with no error indicates absence of the extension, not failure.
func (extensions Extensions) AuthorityKeyIdentifier() (*AuthorityKeyIdentifier, error) {
	for i := range extensions {
		if extensions[i].ObjectId.Equal(oid.OidAuthorityKeyIdentifier) {
			var out AuthorityKeyIdentifier

			err := utils.ParseAsn1(extensions[i].ExtnValue.Bytes, false, &out)
			if err != nil {
				return nil, fmt.Errorf("[AuthorityKeyIdentifier] ParseAsn1 error: %w", err)
			}

			return &out, nil
		}
	}

	return nil, nil
}

// SubjectKeyIdentifier locates and parses the Subject Key Identifier (SKI)
// extension from the Extensions collection.
//
// It iterates through the extensions and returns the first extension whose
// ObjectId matches the Subject Key Identifier OID (oid.OidSubjectKeyIdentifier).
// The extension value is decoded from ASN.1 into a SubjectKeyIdentifier struct.
//
// Returns:
//   - *SubjectKeyIdentifier: the parsed SKI structure if present
//   - error: if ASN.1 decoding fails
//
// If no Subject Key Identifier extension is found, the function returns (nil, nil).
//
// Notes:
//   - The function assumes at most one SKI extension is relevant and returns
//     the first match.
//   - The ExtnValue is expected to be a valid ASN.1-encoded SKI structure.
//   - A nil result with no error indicates absence of the extension, not failure.
func (extensions Extensions) SubjectKeyIdentifier() (*SubjectKeyIdentifier, error) {
	for i := range extensions {
		if extensions[i].ObjectId.Equal(oid.OidSubjectKeyIdentifier) {
			var out SubjectKeyIdentifier

			err := utils.ParseAsn1(extensions[i].ExtnValue.Bytes, false, &out)
			if err != nil {
				return nil, fmt.Errorf("[SubjectKeyIdentifier] ParseAsn1 error: %w", err)
			}

			return &out, nil
		}
	}

	return nil, nil
}

// TODO - handlers for other extensions... key-usage (sign,..)... CSCA: privateKeyUsagePeriod, id-ce-keyUsage (for CA detection?)

type RDNSequence []RelativeDistinguishedNameSET
type RelativeDistinguishedNameSET AttributeList

func ParseRDNSequence(rdnSeq []byte) (*RDNSequence, error) {
	var out RDNSequence

	err := utils.ParseAsn1(rdnSeq, false, &out)
	if err != nil {
		return nil, fmt.Errorf("[ParseRDNSequence] ParseAsn1 error: %w", err)
	}

	return &out, nil
}

func (rdnSet RDNSequence) ByOID(oid asn1.ObjectIdentifier) []byte {
	for _, set := range rdnSet {
		for _, atv := range set {
			if atv.Type.Equal(oid) {
				return bytes.Clone(atv.Values.Bytes)
			}
		}
	}

	return []byte{}
}

func (cert TBSCertificate) IssuerRDN() (*RDNSequence, error) {
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

// TODO - MarshalJSON

type Validity struct {
	NotBefore asn1.RawValue `json:"notBefore"`
	NotAfter  asn1.RawValue `json:"notAfter"`
}

// TODO - MarshalJSON

type Extension struct {
	Raw       asn1.RawContent       `json:"raw"`
	ObjectId  asn1.ObjectIdentifier `json:"objectId"`
	Critical  asn1.Flag             `asn1:"optional,default:false" json:"critical"`
	ExtnValue asn1.RawValue         `json:"extnValue"`
}

// TODO - MarshalJSON

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

func (si *SignerInfo) VerifyWithConfig(config *CMSConfig, sd *SignedData, trustedCerts CertPool) (certChain [][]byte, err error) {
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

	dataToHash, digestAlg, signatureAlg, signature, err = si.prepareVerificationData(config, sd)
	if err != nil {
		return nil, fmt.Errorf("[Verify] prepareVerificationData error: %w", err)
	}

	var digest []byte
	digest, err = config.Hasher.CryptoHashByOid(*digestAlg, dataToHash)
	if err != nil {
		return nil, fmt.Errorf("[Verify] CryptoHashByOid error: %w", err)
	}

	slog.Debug("Verify", "digestAlg", digestAlg.String(), "digest", utils.BytesToHex(digest))

	cert, err := si.selectCertificate(sd)
	if err != nil {
		return nil, fmt.Errorf("[Verify] selectCertificate error: %w", err)
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
		tmpCertChain, err := cert.VerifyWithConfig(config, trustedCerts)
		if err != nil {
			return nil, fmt.Errorf("[Verify] cert.Verify error: %w", err)
		}

		// record the certificate(s) used during verification
		certChain = append(certChain, tmpCertChain...)
	}

	return certChain, nil
}

func (si *SignerInfo) Verify(sd *SignedData, trustedCerts CertPool) (certChain [][]byte, err error) {
	return si.VerifyWithConfig(NewDefaultCMSConfig(), sd, trustedCerts)
}

// prepareVerificationData extracts and validates authenticated attributes
func (si *SignerInfo) prepareVerificationData(config *CMSConfig, sd *SignedData) (dataToHash []byte, digestAlg, signatureAlg *asn1.ObjectIdentifier, signature []byte, err error) {
	if len(si.AuthenticatedAttributes) < 1 {
		return nil, nil, nil, nil, fmt.Errorf("[prepareVerificationData] SignedInfo without AuthenticatedAttributes is NOT supported")
	}

	aaContentType := si.AuthenticatedAttributes.ByOID(oid.OidContentType)
	aaMessageDigest := si.AuthenticatedAttributes.ByOID(oid.OidMessageDigest)
	if aaContentType == nil || aaMessageDigest == nil {
		return nil, nil, nil, nil, fmt.Errorf("[prepareVerificationData] Expected Authenticated-Attribute(s) missing (Content-Type, Message-Digest)")
	}

	var aaContentTypeOID asn1.ObjectIdentifier
	aaContentTypeOID, err = asn1decodeOid(config, aaContentType.Values.Bytes)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("[prepareVerificationData] asn1decodeOid error: %w", err)
	}

	var aaMessageDigestHash []byte
	aaMessageDigestHash, err = asn1decodeBytes(config, aaMessageDigest.Values.Bytes)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("[prepareVerificationData] asn1decodeBytes error: %w", err)
	}

	slog.Debug("prepareVerificationData", "AA Content-Type", aaContentTypeOID.String())
	slog.Debug("prepareVerificationData", "AA Message-Digest", utils.BytesToHex(aaMessageDigestHash))

	// verify Content OID matches Authenticated-Attribute (Content Type)
	if !aaContentTypeOID.Equal(sd.Content.EContentType) {
		return nil, nil, nil, nil, fmt.Errorf("[prepareVerificationData] Content-Type-OID (%s) differs to Authenticated-Attribute (%s)", sd.Content.EContentType.String(), aaContentTypeOID.String())
	}

	var contentHash []byte
	contentHash, err = config.Hasher.CryptoHashByOid(si.DigestAlgorithm.Algorithm, sd.Content.EContent)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("[prepareVerificationData] CryptoHashByOid error: %w", err)
	}

	slog.Debug("prepareVerificationData", "ContentHash", utils.BytesToHex(contentHash))

	//	5.4.  Message Digest Calculation Process (RFC5652)
	if !bytes.Equal(contentHash, aaMessageDigestHash) {
		// invalid content hash
		slog.Debug("prepareVerificationData - invalid content hash", "contentHash", utils.BytesToHex(contentHash), "aaMessageDigestHash", utils.BytesToHex(aaMessageDigestHash))
		return nil, nil, nil, nil, fmt.Errorf("[prepareVerificationData] Invalid content hash (contentHash:%x, aaMessageDigestHash:%x)", contentHash, aaMessageDigestHash)
	}

	dataToHash = si.AuthenticatedAttributes.SetOfAsnBytes()
	digestAlg = &(si.DigestAlgorithm.Algorithm)
	signatureAlg = &(si.DigestEncryptionAlgorithm.Algorithm)
	signature = si.EncryptedDigest

	return dataToHash, digestAlg, signatureAlg, signature, nil
}

// selectCertificate finds the appropriate certificate from the signed data
func (si *SignerInfo) selectCertificate(sd *SignedData) (*Certificate, error) {
	var sdCerts *GenericCertPool = &GenericCertPool{}

	err := sdCerts.Add(sd.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("[selectCertificate] CertPool.Add error: %w", err)
	}

	var tmpCerts []Certificate

	if sdCerts.Count() == 1 {
		// if we only have 1 certificate in the signed-data then we'll just use that
		tmpCerts = append(tmpCerts, sdCerts.certificates...)
	} else if sdCerts.Count() > 1 {
		// pick the certificate(s) if multiple exist
		// TODO - should support other variants also (e.g. issuer+serialNumber).. sid is not always aki
		tmpCerts = sdCerts.BySKI(si.Sid.Bytes)
	}

	if len(tmpCerts) != 1 {
		return nil, fmt.Errorf("[selectCertificate] Expected a single matching Cert from within the SignedData (got:%d) (sid:%x)", len(tmpCerts), si.Sid.FullBytes)
	}

	return &tmpCerts[0], nil
}

func (sd *SignedData) VerifyWithConfig(config *CMSConfig, trustedCerts CertPool) (certChain [][]byte, err error) {
	slog.Debug("SignedData.Verify")

	slog.Debug("Verify", "SignerInfo(cnt)", len(sd.SignerInfos))

	// check that we have some SignedInfos
	if len(sd.SignerInfos) < 1 {
		return nil, fmt.Errorf("[Verify] NO SignerInfos present")
	}

	// for-each signer-info
	for siIdx := range sd.SignerInfos {
		var tmpCertChain [][]byte

		tmpCertChain, err = sd.SignerInfos[siIdx].VerifyWithConfig(config, sd, trustedCerts)
		if err != nil {
			return nil, fmt.Errorf("[Verify] si.Verify(idx:%d) error: %w", siIdx, err)
		}

		certChain = append(certChain, tmpCertChain...)
	}

	return certChain, nil
}

func (sd *SignedData) Verify(trustedCerts CertPool) (certChain [][]byte, err error) {
	return sd.VerifyWithConfig(NewDefaultCMSConfig(), trustedCerts)
}

// verifies that the certificate was signed by one of the certificates in 'trustedCerts'
// NB considers all entries in 'trustedCerts' to be valid signers, so doesn't walk the chain to a root-cert
func (cert *Certificate) VerifyWithConfig(config *CMSConfig, trustedCerts CertPool) (certChain [][]byte, err error) {
	// TODO - currently just verifies the signature... doesn't check anything else... e.g. signing-time-validity...
	//			see 9303p10 5.1 Passive Authentication for detailed overview
	// - for MRTD, country is indirectly validated by passive-auth as it will only provide 'trustedCerts' for the country based on the MRZ

	slog.Debug("CERT.Verify", "Cert(hex)", utils.BytesToHex(cert.Raw))

	// get the parent certificate (authority) key identifier
	var aki *AuthorityKeyIdentifier
	aki, err = cert.TbsCertificate.Extensions.AuthorityKeyIdentifier()
	if err != nil {
		return certChain, fmt.Errorf("[Certificate.Verify] AuthorityKeyIdentifier error: %w", err)
	}
	if aki == nil {
		return certChain, fmt.Errorf("[Certificate.Verify] AKI missing from cert (%x)", cert.Raw)
	}

	// determine the digest-alg for the cert
	var certDigestAlg *asn1.ObjectIdentifier
	certDigestAlg, err = cert.SignatureAlgorithm.DetermineDigestAlgFromSigAlgWithConfig(config)
	if err != nil {
		return certChain, fmt.Errorf("[Certificate.Verify] unable to determine digest-alg from signature-alg: %w", err)
	}

	// calculate the cert digest
	var certDigest []byte
	certDigest, err = config.Hasher.CryptoHashByOid(*certDigestAlg, cert.TbsCertificate.Raw)
	if err != nil {
		return nil, fmt.Errorf("[Certificate.Verify] CryptoHashByOid error: %w", err)
	}

	// get any matching parent certificates
	// NB often >1 due to cross-signing in master-list
	parentCerts := trustedCerts.BySKI(aki.KeyIdentifier) // TODO - other variants? eg issuer/serial

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

func (cert *Certificate) Verify(trustedCerts CertPool) (certChain [][]byte, err error) {
	return cert.VerifyWithConfig(NewDefaultCMSConfig(), trustedCerts)
}

func asn1decodeOid(config *CMSConfig, data []byte) (asn1.ObjectIdentifier, error) {
	var out asn1.ObjectIdentifier

	err := config.Parser.ParseAsn1(data, false, &out)
	if err != nil {
		return nil, fmt.Errorf("[asn1decodeOid] ParseAsn1 error: %w", err)
	}

	return out, nil
}

func asn1decodeBytes(config *CMSConfig, data []byte) ([]byte, error) {
	var out []byte

	err := config.Parser.ParseAsn1(data, false, &out)
	if err != nil {
		return nil, fmt.Errorf("[asn1decodeBytes] ParseAsn1 error: %w", err)
	}

	return out, nil
}

func Asn1decodeSubjectPublicKeyInfo(data []byte) (SubjectPublicKeyInfo, error) {
	var out SubjectPublicKeyInfo

	err := utils.ParseAsn1(data, false, &out)
	if err != nil {
		return SubjectPublicKeyInfo{}, fmt.Errorf("[Asn1decodeSubjectPublicKeyInfo] ParseAsn1 error: %w", err)
	}

	return out, nil
}

type EcNamedCurve struct {
	oid   asn1.ObjectIdentifier
	curve elliptic.Curve
}

func (subPubKeyInfo *SubjectPublicKeyInfo) IsEC() bool {
	// verify Algorithm OID
	var expOid asn1.ObjectIdentifier = oid.OidEcPublicKey
	if !subPubKeyInfo.Algorithm.Algorithm.Equal(expOid) {
		return false
	}

	return true
}

func (subPubKeyInfo *SubjectPublicKeyInfo) EcCurveWithConfig(config *CMSConfig) (curve *elliptic.Curve, err error) {
	/*
	* Note: We avoid using 'ParsePKIXPublicKey' as it follows PKIX standard and only allows names curves,
	*       but passports tend to use specified curves (i.e. curve parameters, even if corresponding to well-known curves)
	 */

	// verify this is an EC key
	if !subPubKeyInfo.IsEC() {
		return nil, fmt.Errorf("[EcCurve] Not an EC key")
	}

	var specDomain *ECSpecifiedDomain
	specDomain, err = ParseECSpecifiedDomain(&subPubKeyInfo.Algorithm)
	if err == nil {
		curve, err = specDomain.EcCurve(config)
		if err != nil {
			return nil, fmt.Errorf("[EcCurve] EcCurve error: %w", err)
		}
	} else {
		/*
		* may be 'named curve'...
		 */
		var tmpOid asn1.ObjectIdentifier

		err = config.Parser.ParseAsn1(subPubKeyInfo.Algorithm.Parameters.FullBytes, false, &tmpOid)
		if err != nil {
			return nil, fmt.Errorf("[EcCurve] ParseAsn1 error: %w", err)
		}

		namedCurves := config.CurveLookup.GetNamedCurves()
		for i := range namedCurves {
			if namedCurves[i].oid.Equal(tmpOid) {
				// found
				curve = &(namedCurves[i].curve)
				break
			}
		}

		if curve == nil {
			// unsupported named curve
			return nil, fmt.Errorf("[EcCurve] Unsupported EC Named Curve (OID:%s)", tmpOid.String())
		}
	}

	return curve, nil
}

func (subPubKeyInfo *SubjectPublicKeyInfo) EcCurve() (curve *elliptic.Curve, err error) {
	return subPubKeyInfo.EcCurveWithConfig(NewDefaultCMSConfig())
}

// EcPubKeyForCurve extracts and decodes the EC public key from the SubjectPublicKeyInfo
// using the caller-provided elliptic curve.
//
// This function does NOT derive or validate the curve from the key itself. Instead,
// it assumes the provided curve is correct and attempts to decode the public key
// bytes (in X9.62 uncompressed/compressed format) against that curve.
//
// Callers MUST ensure that the supplied curve matches the expected domain parameters
// for the key. Providing an incorrect curve may result in decoding failure or,
// worse, successful decoding of an invalid point under the wrong curve.
//
// Returns an error if:
//   - the SubjectPublicKeyInfo does not represent an EC key
//   - the public key bytes cannot be decoded into a valid EC point for the given curve
//
// Security note:
// This function performs minimal validation and does not check whether the point lies
// on the curve beyond what DecodeX962EcPoint enforces. Additional validation may be
// required depending on the trust model.
func (subPubKeyInfo *SubjectPublicKeyInfo) EcPubKeyForCurve(curve elliptic.Curve) (pubKey *cryptoutils.EcPoint, err error) {
	// verify this is an EC key
	if !subPubKeyInfo.IsEC() {
		return nil, fmt.Errorf("[EcPubKeyForCurve] Not an EC key")
	}

	// get the chip's public key
	var chipPubKeyBytes []byte = subPubKeyInfo.SubjectPublicKey.Bytes
	pubKey = cryptoutils.DecodeX962EcPoint(curve, chipPubKeyBytes)
	if pubKey == nil {
		return nil, fmt.Errorf("[EcPubKeyForCurve] DecodeX962EcPoint failed to return pubKey")
	}

	return pubKey, nil
}

// EcCurveAndPubKey resolves the elliptic curve and decodes the EC public key
// from the SubjectPublicKeyInfo.
//
// The function first determines the curve from the key metadata (via EcCurve)
// and attempts to decode the public key using that curve. If decoding fails,
// it may optionally attempt a fallback by trying a set of alternative curves.
//
// The set of alternative curves is controlled by the caller (e.g. via
// getAlternativeCurvesFn). Callers can disable fallback entirely, restrict the
// allowed curves, or enforce strict matching with the advertised curve.
//
// Returns:
//   - curve: pointer to the resolved elliptic curve used for decoding
//   - pubKey: decoded EC point
//   - error: if the key is not EC, the curve cannot be determined, or no valid
//     curve can successfully decode the public key
//
// Behavior:
//   - Validates that the SubjectPublicKeyInfo represents an EC key
//   - Uses the advertised curve first
//   - Optionally falls back to caller-defined alternative curves if decoding fails
//
// Security note:
// Curve fallback may allow successful decoding under a curve different from the
// one advertised in the key metadata. This can indicate malformed, non-compliant,
// or malicious inputs. Callers SHOULD carefully configure or disable fallback
// depending on their trust model. In high-assurance contexts, strict enforcement
// of the advertised curve is typically preferred.
func (subPubKeyInfo *SubjectPublicKeyInfo) EcCurveAndPubKeyWithConfig(config *CMSConfig, allowCurveFallback bool) (curve *elliptic.Curve, pubKey *cryptoutils.EcPoint, err error) {
	// verify this is an EC key
	if !subPubKeyInfo.IsEC() {
		return nil, nil, fmt.Errorf("[EcCurveAndPubKey] Not an EC key")
	}

	curve, err = subPubKeyInfo.EcCurveWithConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("[EcCurveAndPubKey] EcCurve error: %w", err)
	}

	pubKey, err = subPubKeyInfo.EcPubKeyForCurve(*curve)
	if err != nil {
		if !allowCurveFallback {
			return nil, nil, fmt.Errorf("[EcCurveAndPubKey] EcPubKeyForCurve error: %w", err)
		} else {
			// log warning AND reset error, as we'll be attempting alternative curves
			slog.Warn("[EcCurveAndPubKey] unable to get PublicKey for Curve, possible Curve mismatch, trying alternative curves", "origCurve", getCurveName(*curve), "subjectPublicKey", utils.BytesToHex(subPubKeyInfo.SubjectPublicKey.Bytes))
			err = nil
		}
	} else {
		// finish if no error
		return curve, pubKey, nil
	}

	// try to find an alternative curve, as the advertised curve was not valid for the public-key
	{
		slog.Debug("[EcCurveAndPubKey] evaluating alternative curves...")

		for _, altCurve := range getAlternativeCurvesFn(*curve) {
			altCurveName := getCurveName(altCurve)
			slog.Debug("[EcCurveAndPubKey] trying alternative curve", "curve", altCurveName)

			pubKey, err := subPubKeyInfo.EcPubKeyForCurve(altCurve)
			if err != nil {
				slog.Debug("[EcCurveAndPubKey] alternative curve not valid for public-key", "altCurve", altCurveName)
			}

			if pubKey != nil {
				slog.Warn("[EcCurveAndPubKey] valid alternative curve found", "origCurve", getCurveName(*curve), "altCurve", altCurveName, "subjectPublicKey", utils.BytesToHex(subPubKeyInfo.SubjectPublicKey.Bytes))
				return &altCurve, pubKey, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("[EcCurveAndPubKey] Unable to get PublicKey")
}

func (subPubKeyInfo *SubjectPublicKeyInfo) EcCurveAndPubKey(allowCurveFallback bool) (curve *elliptic.Curve, pubKey *cryptoutils.EcPoint, err error) {
	return subPubKeyInfo.EcCurveAndPubKeyWithConfig(NewDefaultCMSConfig(), allowCurveFallback)
}

func (subPubKeyInfo *SubjectPublicKeyInfo) IsRSA() bool {
	// verify Algorithm OID
	var expOid asn1.ObjectIdentifier = oid.OidRsaEncryption
	if !subPubKeyInfo.Algorithm.Algorithm.Equal(expOid) {
		return false
	}

	return true
}

func (subPubKeyInfo *SubjectPublicKeyInfo) RsaPubKey() (*cryptoutils.RsaPublicKey, error) {
	var err error
	var out cryptoutils.RsaPublicKey

	// verify this is an RSA key
	if !subPubKeyInfo.IsRSA() {
		return nil, fmt.Errorf("[RsaPubKey] Not an RSA key")
	}

	err = utils.ParseAsn1(subPubKeyInfo.SubjectPublicKey.Bytes, false, &out)
	if err != nil {
		return nil, fmt.Errorf("[RsaPubKey] ParseAsn1 error: %w", err)
	}

	err = validateRsaPublicKey(out)
	if err != nil {
		return nil, fmt.Errorf("[RsaPubKey] validateRSAPublicKey error: %w", err)
	}

	return &out, nil
}

func validateRsaPublicKey(pubKey cryptoutils.RsaPublicKey) error {
	if pubKey.N == nil || pubKey.N.Sign() <= 0 {
		return fmt.Errorf("[validateRSAPublicKey] invalid modulus N")
	}

	if pubKey.E <= 1 {
		return fmt.Errorf("[validateRSAPublicKey] invalid exponent E")
	}

	if pubKey.E%2 == 0 { // even check
		return fmt.Errorf("[validateRSAPublicKey] exponent must be odd")
	}

	return nil
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
func (specDomain ECSpecifiedDomain) EcCurve(config *CMSConfig) (*elliptic.Curve, error) {
	slog.Debug("EcCurve", "Params", utils.BytesToHex(specDomain.FieldId.Parameters.Bytes))

	// NB sometimes there can be leading zero
	specDomainPBytes := utils.TrimLeadingZeroBytes(specDomain.FieldId.Parameters.Bytes)

	// look for matching 'standard' curve
	// NB we currently expect the use of standard curve, we may need to support custom curves in the future (but hopefully not)
	lookupCurves := config.CurveLookup.GetLookupCurves()
	for i := 0; i < len(lookupCurves); i++ {
		var ec elliptic.Curve = lookupCurves[i]

		// match using the 'prime field' (P)
		if slices.Equal(ec.Params().P.Bytes(), specDomainPBytes) {
			slog.Debug("EcCurve", "curveIdx", i, "specDomain", specDomain)
			return &ec, nil
		}
	}

	return nil, fmt.Errorf("(ECSpecifiedDomain.EcCurve) unsupported CA EC (Params:%x) (Raw:%x)", specDomain.FieldId.Parameters.Bytes, specDomain.Raw)
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

// determines the digest algorithm from the provided signature algorithm
// e.g. OidSha512WithRSAEncryption -> OidHashAlgorithmSHA512
func (signature AlgorithmIdentifier) DetermineDigestAlgFromSigAlgWithConfig(config *CMSConfig) (*asn1.ObjectIdentifier, error) {
	var digestAlg asn1.ObjectIdentifier

	if signature.Algorithm.Equal(oid.OidRsaSsaPss) {
		/*
		* special handling for RSA-PSS
		 */
		var tmpParams RsaSsaPssParams

		err := config.Parser.ParseAsn1(signature.Parameters.FullBytes, false, &tmpParams)
		if err != nil {
			return nil, fmt.Errorf("(AlgorithmIdentifier.DetermineDigestAlg) error: %s", err)
		}

		digestAlg = tmpParams.HashAlgorithm.Algorithm
	} else {
		/*
		* regular OID lookup for others
		 */
		var ok bool

		digestAlg, ok = config.SigAlgMap[signature.Algorithm.String()]

		if !ok {
			return nil, fmt.Errorf("(AlgorithmIdentifier.DetermineDigestAlg) unable to resolve digest algorithm from signature algorithm (sig-oid: %s)", signature.Algorithm.String())
		}
	}

	return &digestAlg, nil
}

func (signature AlgorithmIdentifier) DetermineDigestAlgFromSigAlg() (*asn1.ObjectIdentifier, error) {
	return signature.DetermineDigestAlgFromSigAlgWithConfig(NewDefaultCMSConfig())
}
