package document

import (
	"bytes"
	"encoding/asn1"
	"fmt"
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

func isValidEContentType(eContentOid asn1.ObjectIdentifier) bool {
	if eContentOid.Equal(oid.OidLdsSecurityObject) {
		return true
	} else if eContentOid.Equal(oid.OidIdData) {
		// observed on China passport
		return true
	}

	return false
}

func NewSOD(data []byte) (*SOD, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *SOD = new(SOD)

	out.RawData = slices.Clone(data)

	nodes, err := tlv.Decode(out.RawData)
	if err != nil {
		return nil, fmt.Errorf("[NewSOD] error: %w", err)
	}

	rootNode := nodes.GetNode(SODTag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", SODTag)
	}

	{
		var sd *cms.SignedData
		var err error

		sd, err = cms.ParseSignedData(rootNode.GetNode(0x30).Encode())
		if err != nil {
			return nil, err
		}

		out.SD = sd

		// verify the content-type is as expected
		if !isValidEContentType(sd.Content.EContentType) {
			return nil, fmt.Errorf("incorrect ContentType (got:%s)", sd.Content.EContentType.String())
		}
		eContent := sd.Content.EContent

		out.LdsSecurityObject, err = parseLdsSecurityObject(eContent)
		if err != nil {
			return nil, err
		}
	}

	return out, nil
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
		return nil, fmt.Errorf("asn1 parsing error: %s", err)
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
func (sod SOD) GetCertCountryAlpha2() (string, error) {
	var sdCerts *cms.GenericCertPool = &cms.GenericCertPool{}

	err := sdCerts.Add(sod.SD.Certificates.Bytes)
	if err != nil {
		return "", fmt.Errorf("[GetCountryAlpha2] certPool.Add error: %w", err)
	}

	certs := sdCerts.GetAll()

	countries := make(map[string]struct{})

	for i := range certs {
		tmpCountry := certs[i].TbsCertificate.GetIssuerRDN().GetByOID(oid.OidCountryName)
		countries[string(tmpCountry)] = struct{}{}
	}

	if len(countries) != 1 {
		return "", fmt.Errorf("[GetCertCountryAlpha2] unable to determine single country (len:%1d) (countries:%v)", len(countries), countries)
	}

	var country string
	for tmpCountry := range countries {
		country = tmpCountry
		break // stop after first key
	}

	return country, nil
}
