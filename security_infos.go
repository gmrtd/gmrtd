package gmrtd

import (
	"encoding/asn1"
	"fmt"
	"log"
	"log/slog"
	"strings"
)

// 9.2.10 EFDIRInfo

const id_EFDIR = id_icao_mrtd_security + ".13"

// PACEInfo
// IF OID is a child under... id_PACE_DH_GM | id_PACE_ECDH_GM | id_PACE_DH_IM | id_PACE_ECDH_IM | id_PACE_ECDH_CAM
func isPACEInfo(oid string) bool {
	return strings.HasPrefix(oid, id_PACE_DH_GM+".") || strings.HasPrefix(oid, id_PACE_ECDH_GM+".") || strings.HasPrefix(oid, id_PACE_DH_IM+".") || strings.HasPrefix(oid, id_PACE_ECDH_IM+".") || strings.HasPrefix(oid, id_PACE_ECDH_CAM+".")
}

// PACEDomainParameterInfo
// IF OID exactly matches... id_PACE_DH_GM | id_PACE_ECDH_GM | id_PACE_DH_IM | id_PACE_ECDH_IM | id_PACE_ECDH_CAM
func isPACEDomainParameterInfo(oid string) bool {
	return (oid == id_PACE_DH_GM) || (oid == id_PACE_ECDH_GM) || (oid == id_PACE_DH_IM) || (oid == id_PACE_ECDH_IM) || (oid == id_PACE_ECDH_CAM)
}

// ActiveAuthenticationInfo
// IF OID exactly matches... id_icao_mrtd_security_aaProtocolObject
func isActiveAuthenticationInfo(oid string) bool {
	return oid == id_icao_mrtd_security_aaProtocolObject
}

// ChipAuthenticationInfo
// IF OID is a child under... id_PK_DH | id_PK_ECDH
func isChipAuthenticationInfo(oid string) bool {
	return strings.HasPrefix(oid, id_CA_DH+".") || strings.HasPrefix(oid, id_CA_ECDH+".")
}

// ChipAuthenticationPublicKeyInfo
// IF OID exactly matches... id_PK_DH or id_PK_ECDH
func isChipAuthenticationPublicKeyInfo(oid string) bool {
	return (oid == id_PK_DH) || (oid == id_PK_ECDH)
}

// TerminalAuthenticationInfo
// If OID starts/matches... id_TA		(not clear from spec... seems to imply id_TA)
func isTerminalAuthenticationInfo(oid string) bool {
	return strings.HasPrefix(oid, id_TA)
}

// EFDIRInfo
// IF OID exactly matches... id_EFDIR
func isEFDIRInfo(oid string) bool {
	return oid == id_EFDIR
}

type SecurityInfoOid struct {
	Raw      asn1.RawContent
	Protocol asn1.ObjectIdentifier `asn1:""`
}
type SecurityInfoOidSET []SecurityInfoOid

type PaceInfo struct {
	Protocol    asn1.ObjectIdentifier
	Version     int
	ParameterId int `asn1:"optional"`
}

type PaceDomainParameterInfo struct {
	Protocol        asn1.ObjectIdentifier
	DomainParameter AlgorithmIdentifier
	ParameterId     int `asn1:"optional"`
}

type ActiveAuthenticationInfo struct {
	Protocol           asn1.ObjectIdentifier
	Version            int
	SignatureAlgorithm asn1.ObjectIdentifier
}

type ChipAuthenticationInfo struct {
	Protocol asn1.ObjectIdentifier
	Version  int
	KeyId    int `asn1:"optional"`
}

func (info ChipAuthenticationInfo) String() string {
	return fmt.Sprintf("Protocol:%s, Version:%d, KeyId:%d", info.Protocol.String(), info.Version, info.KeyId)
}

type ChipAuthenticationPublicKeyInfo struct {
	Protocol                    asn1.ObjectIdentifier
	ChipAuthenticationPublicKey SubjectPublicKeyInfo
	KeyId                       int `asn1:"optional"`
}

type SubjectPublicKeyInfo struct {
	Algorithm        AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters int `asn1:"optional"` // TODO - spec technically says ANY type
}

type TerminalAuthenticationInfo struct {
	Protocol asn1.ObjectIdentifier
	Version  int
}

type EFDirInfo struct {
	Protocol asn1.ObjectIdentifier
	EFDir    []byte
}

type SecurityInfos struct {
	PaceInfos            []PaceInfo
	PaceDomainParamInfos []PaceDomainParameterInfo
	ActiveAuthInfos      []ActiveAuthenticationInfo
	ChipAuthInfos        []ChipAuthenticationInfo
	ChipAuthPubKeyInfos  []ChipAuthenticationPublicKeyInfo
	TermAuthInfos        []TerminalAuthenticationInfo
	EfDirInfos           []EFDirInfo
	UnhandledInfos       []UnhandledInfo
}

type UnhandledInfo struct {
	Protocol asn1.ObjectIdentifier
	RawData  []byte
}

// isPartiallyParsed - if false then panics if there is any data remaining after the parsing
func parseAsn1[T any](data []byte, isPartiallyParsed bool, out *T) {
	rest, err := asn1.Unmarshal(data, out)
	if err != nil {
		log.Panic(err)
	}
	if isPartiallyParsed && (len(rest) > 0) {
		log.Panicf("Unexpected data remaining after ASN1 parsing (Data:%x) (Remaining:%x)", data, rest)
	}
}

func DecodeSecurityInfos(secInfoData []byte) *SecurityInfos {
	var out *SecurityInfos = &SecurityInfos{}
	var secInfoOids SecurityInfoOidSET

	// decode OID headers (preserving raw-content)
	// we only read the OID, so we expect unparsed data to remain
	parseAsn1(secInfoData, true, &secInfoOids)

	// TODO - inspect data and check.. e.g. expected OIDs / version / ...
	//			e.g. paceInfo version should be 1
	//			e.g. ActiveAuthenticationInfo Version must be 1

	// process each record, based on the record-type (derived from OID)
	for i := range secInfoOids {
		oid := secInfoOids[i].Protocol.String()
		data := secInfoOids[i].Raw

		slog.Debug("parsing secInfo", "oid", oid, "tlv", TlvDecode(data))

		if isPACEInfo(oid) {
			var paceInfo PaceInfo
			parseAsn1(data, false, &paceInfo)
			out.PaceInfos = append(out.PaceInfos, paceInfo)
		} else if isPACEDomainParameterInfo(oid) {
			var paceDomainParamInfo PaceDomainParameterInfo
			parseAsn1(data, false, &paceDomainParamInfo)
			out.PaceDomainParamInfos = append(out.PaceDomainParamInfos, paceDomainParamInfo)
		} else if isActiveAuthenticationInfo(oid) {
			var activeAuthInfo ActiveAuthenticationInfo
			parseAsn1(data, false, &activeAuthInfo)
			out.ActiveAuthInfos = append(out.ActiveAuthInfos, activeAuthInfo)
		} else if isChipAuthenticationInfo(oid) {
			var chipAuthInfo ChipAuthenticationInfo
			parseAsn1(data, false, &chipAuthInfo)
			out.ChipAuthInfos = append(out.ChipAuthInfos, chipAuthInfo)
		} else if isChipAuthenticationPublicKeyInfo(oid) {
			var chipAuthPubKeyInfo ChipAuthenticationPublicKeyInfo
			parseAsn1(data, false, &chipAuthPubKeyInfo)
			out.ChipAuthPubKeyInfos = append(out.ChipAuthPubKeyInfos, chipAuthPubKeyInfo)
		} else if isTerminalAuthenticationInfo(oid) {
			var termAuthInfo TerminalAuthenticationInfo
			parseAsn1(data, false, &termAuthInfo)
			out.TermAuthInfos = append(out.TermAuthInfos, termAuthInfo)
		} else if isEFDIRInfo(oid) {
			var efDirInfo EFDirInfo
			parseAsn1(data, false, &efDirInfo)
			out.EfDirInfos = append(out.EfDirInfos, efDirInfo)
		} else {
			// unsupported - so simply record
			var unhandledInfo UnhandledInfo = UnhandledInfo{Protocol: secInfoOids[i].Protocol, RawData: secInfoOids[i].Raw}
			out.UnhandledInfos = append(out.UnhandledInfos, unhandledInfo)
		}
	}

	return out
}
