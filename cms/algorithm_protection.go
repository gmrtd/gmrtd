package cms

import (
	"bytes"
	"fmt"

	"github.com/gmrtd/gmrtd/oid"
)

//	CMSAlgorithmProtection ::= SEQUENCE {
//	  digestAlgorithm         DigestAlgorithmIdentifier,
//	  signatureAlgorithm  [1] SignatureAlgorithmIdentifier OPTIONAL,
//	  macAlgorithm        [2] MessageAuthenticationCodeAlgorithm OPTIONAL }
//
// https://datatracker.ietf.org/doc/html/rfc6211#section-2
type CMSAlgorithmProtection struct {
	DigestAlgorithm    AlgorithmIdentifier
	SignatureAlgorithm AlgorithmIdentifier `asn1:"optional,tag:1"`
	MacAlgorithm       AlgorithmIdentifier `asn1:"optional,tag:2"`
}

// verifyAlgorithmProtection checks the optional CMSAlgorithmProtection signed attribute
// (RFC 6211) against the SignerInfo's own algorithm identifiers. Those identifiers are not
// covered by the signature, so without this check they could be substituted undetected.
func (si *SignerInfo) verifyAlgorithmProtection(config *CMSConfig) error {
	var attr *Attribute
	for i := range si.AuthenticatedAttributes {
		if !si.AuthenticatedAttributes[i].Type.Equal(oid.OidCmsAlgorithmProtection) {
			continue
		}
		if attr != nil {
			return fmt.Errorf("[verifyAlgorithmProtection] CMSAlgorithmProtection attribute present more than once")
		}
		attr = &si.AuthenticatedAttributes[i]
	}
	if attr == nil {
		return nil
	}

	var ap CMSAlgorithmProtection
	// allowExtraData=false also rejects a SET containing more than one value (RFC 6211 §2)
	if err := config.Parser.ParseAsn1(attr.Values.Bytes, false, &ap); err != nil {
		return fmt.Errorf("[verifyAlgorithmProtection] asn1 parsing error: %w", err)
	}

	// SignedData requires signatureAlgorithm, and macAlgorithm only applies to AuthenticatedData (RFC 6211 §2)
	if ap.SignatureAlgorithm.Algorithm == nil || ap.MacAlgorithm.Algorithm != nil {
		return fmt.Errorf("[verifyAlgorithmProtection] CMSAlgorithmProtection must contain signatureAlgorithm and not macAlgorithm")
	}

	if !algorithmIdentifiersEqual(ap.DigestAlgorithm, si.DigestAlgorithm) {
		return fmt.Errorf("[verifyAlgorithmProtection] digestAlgorithm (%s) differs to CMSAlgorithmProtection (%s)", si.DigestAlgorithm.Algorithm.String(), ap.DigestAlgorithm.Algorithm.String())
	}

	if !algorithmIdentifiersEqual(ap.SignatureAlgorithm, si.DigestEncryptionAlgorithm) {
		return fmt.Errorf("[verifyAlgorithmProtection] signatureAlgorithm (%s) differs to CMSAlgorithmProtection (%s)", si.DigestEncryptionAlgorithm.Algorithm.String(), ap.SignatureAlgorithm.Algorithm.String())
	}

	return nil
}

// algorithmIdentifiersEqual compares both the OID and the encoded parameters, as the
// parameters carry security-relevant choices (e.g. the RSASSA-PSS hash and salt length).
func algorithmIdentifiersEqual(a, b AlgorithmIdentifier) bool {
	return a.Algorithm.Equal(b.Algorithm) && bytes.Equal(a.Parameters.FullBytes, b.Parameters.FullBytes)
}
