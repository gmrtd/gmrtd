package gmrtd

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"slices"
)

// TODO - 2 versions of SOD... v1 (preferred) and legacy format v0
//			- current code is based on v1... need to also check for v0.. i.e. is it just LDS/Unicode data?

const SODTag = 0x77

type SOD struct {
	RawData []byte
	// nodes   *TlvNodes
	LdsSecurityObject *LDSSecurityObject
}

func NewSOD(data []byte) (*SOD, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *SOD = new(SOD)

	out.RawData = slices.Clone(data)

	nodes := TlvDecode(out.RawData)

	rootNode := nodes.GetNode(SODTag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", SODTag)
	}

	{
		var sd *SignedData
		var err error

		sd, err = parseSignedData(rootNode.GetNode(0x30).Encode())
		if err != nil {
			return nil, err
		}

		// verify the content-type is as expected
		if !sd.SD2.Content.EContentType.Equal(oidLdsSecurityObject) {
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

// TODO - maybe handle this internally
type SignedData struct {
	Oid asn1.ObjectIdentifier ``
	SD2 SignedData2           `asn1:"explicit,tag:0"` // TODO - naming?
}

type SignedData2 struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	Content          EncapContentInfo           ``
	Certificates     []asn1.RawValue            `asn1:"optional,set,tag:0"`
	CRLs             []asn1.RawValue            `asn1:"optional,set,tag:1"`
	SignerInfos      []SignerInfo               `asn1:"set"`
}

type SignerInfo struct {
	Version                   int                      `asn1:"default:1"`
	IssuerAndSerialNumber     IssuerAndSerial          ``
	DigestAlgorithm           pkix.AlgorithmIdentifier ``
	AuthenticatedAttributes   AttributeList            `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier ``
	EncryptedDigest           []byte                   ``
	UnauthenticatedAttributes AttributeList            `asn1:"optional,tag:1"`
}

type IssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}
type AttributeList []Attribute

type EncapContentInfo struct {
	EContentType asn1.ObjectIdentifier ``
	EContent     []byte                `asn1:"explicit,tag:0"` // contains LDSSecurityObject
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

type LDSSecurityObject struct {
	Version             int                      ``
	HashAlgorithm       pkix.AlgorithmIdentifier ``
	DataGroupHashValues []DataGroupHash          ``
	LdsVersionInfo      LDSVersionInfo           `asn1:"optional"`
}

type DataGroupHash struct {
	DataGroupNumber    int    ``
	DataGroupHashValue []byte ``
}

// TODO - present but empty strings if not present in parsed data
type LDSVersionInfo struct {
	LdsVersion     string ``
	UnicodeVersion string ``
}

func parseLdsSecurityObject(data []byte) (*LDSSecurityObject, error) {
	var err error
	var securityObject LDSSecurityObject

	err = parseAsn1(data, false, &securityObject)
	if err != nil {
		return nil, fmt.Errorf("asn1 parsing error: %s", err)
	}

	// TODO - data verification... e.g. v0/1 differences, such as presence of LDSVersionInfo

	return &securityObject, nil
}
