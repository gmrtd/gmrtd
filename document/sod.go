package document

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"slices"

	cms "github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

/*
* 2 versions of SoD are currently supported (v0/v1)
*
* v1 introduces LDSVersionInfo to include LDS/Unicode version information within the SoD
 */

const SODTag = 0x77

type SOD struct {
	RawData           []byte             `json:"rawData,omitempty"`
	SD                *cms.SignedData    `json:"sd,omitempty"`
	LdsSecurityObject *LDSSecurityObject `json:"ldsSecurityObject,omitempty"`
}

type LDSSecurityObject struct {
	Version             int                     `json:"version,omitempty"`
	HashAlgorithm       cms.AlgorithmIdentifier `json:"hashAlgorithm,omitempty"`
	DataGroupHashValues []DataGroupHash         `json:"dataGroupHashValues,omitempty"`
	LdsVersionInfo      LDSVersionInfo          `asn1:"optional" json:"ldsVersionInfo"`
}

type DataGroupHash struct {
	DataGroupNumber    int    `json:"dataGroupNumber"`
	DataGroupHashValue []byte `json:"dataGroupHashValue"`
}

// NB present but empty strings if not present in parsed data (i.e. older version of EF.SOD)
type LDSVersionInfo struct {
	LdsVersion     string `json:"ldsVersion,omitempty"`
	UnicodeVersion string `json:"unicodeVersion,omitempty"`
}

func NewSOD(data []byte) (*SOD, error) {
	var err error

	if len(data) < 1 {
		return nil, nil
	}

	var out *SOD = new(SOD)

	out.RawData = slices.Clone(data)

	// extract the content from the root tag.. and parse the SignedData
	{
		var sdBytes []byte

		sdBytes, err = tlv.UnwrapTag(SODTag, out.RawData)
		if err != nil {
			return nil, fmt.Errorf("[NewSOD] UnwrapTag error: %w", err)
		}

		out.SD, err = parseSignedDataWithDecodeEncodeRetry(sdBytes)
		if err != nil {
			return nil, fmt.Errorf("[NewSOD] parseSignedDataWithDecodeEncodeRetry error: %w", err)
		}
	}

	// verify the content-type is as expected
	if !isValidEContentType(out.SD.Content.EContentType) {
		return nil, fmt.Errorf("[NewSOD] Incorrect ContentType (got:%s)", out.SD.Content.EContentType.String())
	}

	out.LdsSecurityObject, err = parseLdsSecurityObject(out.SD.Content.EContent)
	if err != nil {
		return nil, fmt.Errorf("[NewSOD] parseLdsSecurityObject error: %w", err)
	}

	return out, nil
}

// parseSignedDataWithDecodeEncodeRetry attempts to parse a CMS SignedData
// structure from the provided DER-encoded input.
//
// In the common case, it delegates directly to cms.ParseSignedData. However,
// some real-world inputs (notably certain NZ-issued CMS payloads) use
// indefinite-length ASN.1 encodings, which are not supported by the Go ASN.1
// parser and will cause parsing to fail.
//
// As a defensive fallback, this function performs a TLV decode → re-encode
// pass to normalise the input into a definite-length encoding before retrying
// parsing. This is only attempted if the initial parse fails.
//
// IMPORTANT:
//   - The decode/encode path is intentionally used as a last resort.
//   - It should not be treated as a general-purpose normalisation step.
//   - Any failure during the fallback is returned as an error.
//   - This exists for interoperability, not as a correctness guarantee.
func parseSignedDataWithDecodeEncodeRetry(data []byte) (*cms.SignedData, error) {
	var sd *cms.SignedData
	var err error

	sd, err = cms.ParseSignedData(data)
	if err != nil {
		slog.Warn("parseSignedDataWithDecodeEncodeRetry - error parsing SignedData, will retry after TLV Decode/Encode cycle", "error", err.Error())

		sdBytes2, err := tlv.DecodeEncode(data)
		if err != nil {
			return nil, fmt.Errorf("[parseSignedDataWithDecodeEncodeRetry] TLV.DecodeEncode error: %w", err)
		}

		sd, err = cms.ParseSignedData(sdBytes2)
		if err != nil {
			return nil, fmt.Errorf("[parseSignedDataWithDecodeEncodeRetry] ParseSignedData(2nd attempt) error: %w", err)
		}
	}

	return sd, nil
}

func isValidEContentType(eContentOid asn1.ObjectIdentifier) bool {
	if eContentOid.Equal(oid.OidLdsSecurityObject) {
		return true
	} else if eContentOid.Equal(oid.OidIdData) {
		// observed on China passport
		return true
	}

	return false
}

func (sod SOD) haveLdsVersionInfo() bool {
	if sod.LdsSecurityObject != nil {
		if (len(sod.LdsSecurityObject.LdsVersionInfo.LdsVersion) > 0) &&
			(len(sod.LdsSecurityObject.LdsVersionInfo.UnicodeVersion) > 0) {
			// NB only considered present if we have values for both Lds/Unicode version
			return true
		}
	}

	return false
}

func (sod SOD) ldsVersion() string {
	if sod.haveLdsVersionInfo() {
		return sod.LdsSecurityObject.LdsVersionInfo.LdsVersion
	}

	return ""
}

func (sod SOD) unicodeVersion() string {
	if sod.haveLdsVersionInfo() {
		return sod.LdsSecurityObject.LdsVersionInfo.UnicodeVersion
	}

	return ""
}

func parseLdsSecurityObject(data []byte) (*LDSSecurityObject, error) {
	var err error
	var securityObject LDSSecurityObject

	err = utils.ParseAsn1(data, false, &securityObject)
	if err != nil {
		return nil, fmt.Errorf("[parseLdsSecurityObject] ParseAsn1 error: %s", err)
	}

	// NB main difference between v0 and v1 is the presence of LDSVersionInfo in v1

	return &securityObject, nil
}

// returns: hash for DG, or nil if not present
func (sod SOD) DgHash(dgNumber int) []byte {
	if sod.LdsSecurityObject != nil {
		for _, dgHashValue := range sod.LdsSecurityObject.DataGroupHashValues {
			if dgHashValue.DataGroupNumber == dgNumber {
				return bytes.Clone(dgHashValue.DataGroupHashValue)
			}
		}
	}

	return nil
}

func (sod SOD) HasDgHash(dgNumber int) bool {
	return len(sod.DgHash(dgNumber)) > 0
}

// determines the country from the certificate (DSC)
func (sod SOD) CertCountryAlpha2() (string, error) {
	var sdCerts *cms.GenericCertPool = &cms.GenericCertPool{}

	err := sdCerts.Add(sod.SD.Certificates.Bytes)
	if err != nil {
		return "", fmt.Errorf("[CertCountryAlpha2] certPool.Add error: %w", err)
	}

	certs := sdCerts.All()

	countries := make(map[string]struct{})

	for i := range certs {
		tmpCountry := certs[i].TbsCertificate.IssuerRDN().ByOID(oid.OidCountryName)
		countries[string(tmpCountry)] = struct{}{}
	}

	if len(countries) != 1 {
		return "", fmt.Errorf("[CertCountryAlpha2] unable to determine single country (len:%1d) (countries:%v)", len(countries), countries)
	}

	var country string
	for tmpCountry := range countries {
		country = tmpCountry
		break // stop after first key
	}

	return country, nil
}
