package document

import (
	"fmt"
	"slices"

	cms "github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

// TODO - 2 versions of SOD... v1 (preferred) and legacy format v0
//			- current code is based on v1... need to also check for v0.. i.e. is it just LDS/Unicode data?

const SODTag = 0x77

type SOD struct {
	RawData           []byte
	SD                *cms.SignedData
	LdsSecurityObject *LDSSecurityObject
}

func NewSOD(data []byte) (*SOD, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *SOD = new(SOD)

	out.RawData = slices.Clone(data)

	nodes := tlv.TlvDecode(out.RawData)

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
		if !sd.SD2.Content.EContentType.Equal(oid.OidLdsSecurityObject) {
			return nil, fmt.Errorf("incorrect ContentType (got:%s)", sd.SD2.Content.EContentType.String())
		}
		eContent := sd.SD2.Content.EContent

		out.LdsSecurityObject, err = parseLdsSecurityObject(eContent)
		if err != nil {
			return nil, err
		}
	}

	return out, nil
}

func (sod SOD) ldsVersion() string {
	if sod.LdsSecurityObject != nil {
		return sod.LdsSecurityObject.LdsVersionInfo.LdsVersion
	}

	return ""
}

func (sod SOD) unicodeVersion() string {
	if sod.LdsSecurityObject != nil {
		return sod.LdsSecurityObject.LdsVersionInfo.UnicodeVersion
	}

	return ""
}

type LDSSecurityObject struct {
	Version             int
	HashAlgorithm       cms.AlgorithmIdentifier
	DataGroupHashValues []DataGroupHash
	LdsVersionInfo      LDSVersionInfo `asn1:"optional"`
}

type DataGroupHash struct {
	DataGroupNumber    int
	DataGroupHashValue []byte
}

// NB present but empty strings if not present in parsed data (i.e. older version of EF.SOD)
type LDSVersionInfo struct {
	LdsVersion     string
	UnicodeVersion string
}

func parseLdsSecurityObject(data []byte) (*LDSSecurityObject, error) {
	var err error
	var securityObject LDSSecurityObject

	err = utils.ParseAsn1(data, false, &securityObject)
	if err != nil {
		return nil, fmt.Errorf("asn1 parsing error: %s", err)
	}

	// TODO - data verification... e.g. v0/1 differences, such as presence of LDSVersionInfo

	return &securityObject, nil
}
