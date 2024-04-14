package gmrtd

import (
	"encoding/asn1"
	"fmt"
	"log/slog"
	"strings"
)

// 9.2.10 EFDIRInfo
// TODO - move to OID
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
// TODO - why does above comment indicate something different to what is in code?
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
func parseAsn1[T any](data []byte, isPartiallyParsed bool, out *T) (err error) {
	rest, err := asn1.Unmarshal(data, out)
	if err != nil {
		return err
		//		log.Panic(err)
	}

	// TODO - isPartiallyParsed - seems opposite to comment?
	if isPartiallyParsed && (len(rest) > 0) {
		return fmt.Errorf("unexpected data remaining after ASN1 parsing (Data:%x) (Remaining:%x)", data, rest)
	}

	return nil
}

// TODO - currently fails if anything wrong... maybe we should be more tolerant, but record issues?
func DecodeSecurityInfos(secInfoData []byte) (secInfos *SecurityInfos, err error) {
	var secInfoOids SecurityInfoOidSET

	// decode OID headers (preserving raw-content)
	// we only read the OID, so we expect unparsed data to remain
	err = parseAsn1(secInfoData, true, &secInfoOids)
	if err != nil {
		return nil, err
	}

	secInfos = &SecurityInfos{}

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
			err = parseAsn1(data, false, &paceInfo)
			if err != nil {
				return nil, err
			}
			secInfos.PaceInfos = append(secInfos.PaceInfos, paceInfo)
		} else if isPACEDomainParameterInfo(oid) {
			var paceDomainParamInfo PaceDomainParameterInfo
			err = parseAsn1(data, false, &paceDomainParamInfo)
			if err != nil {
				return nil, err
			}
			secInfos.PaceDomainParamInfos = append(secInfos.PaceDomainParamInfos, paceDomainParamInfo)
		} else if isActiveAuthenticationInfo(oid) {
			var activeAuthInfo ActiveAuthenticationInfo
			err = parseAsn1(data, false, &activeAuthInfo)
			if err != nil {
				return nil, err
			}
			secInfos.ActiveAuthInfos = append(secInfos.ActiveAuthInfos, activeAuthInfo)
		} else if isChipAuthenticationInfo(oid) {
			var chipAuthInfo ChipAuthenticationInfo
			err = parseAsn1(data, false, &chipAuthInfo)
			if err != nil {
				return nil, err
			}
			secInfos.ChipAuthInfos = append(secInfos.ChipAuthInfos, chipAuthInfo)
		} else if isChipAuthenticationPublicKeyInfo(oid) {
			var chipAuthPubKeyInfo ChipAuthenticationPublicKeyInfo
			err = parseAsn1(data, false, &chipAuthPubKeyInfo)
			if err != nil {
				return nil, err
			}
			secInfos.ChipAuthPubKeyInfos = append(secInfos.ChipAuthPubKeyInfos, chipAuthPubKeyInfo)
		} else if isTerminalAuthenticationInfo(oid) {
			var termAuthInfo TerminalAuthenticationInfo
			err = parseAsn1(data, false, &termAuthInfo)
			if err != nil {
				return nil, err
			}
			secInfos.TermAuthInfos = append(secInfos.TermAuthInfos, termAuthInfo)
		} else if isEFDIRInfo(oid) {
			var efDirInfo EFDirInfo
			err = parseAsn1(data, false, &efDirInfo)
			if err != nil {
				return nil, err
			}
			secInfos.EfDirInfos = append(secInfos.EfDirInfos, efDirInfo)
		} else {
			// unsupported - so simply record
			var unhandledInfo UnhandledInfo = UnhandledInfo{Protocol: secInfoOids[i].Protocol, RawData: secInfoOids[i].Raw}
			secInfos.UnhandledInfos = append(secInfos.UnhandledInfos, unhandledInfo)
		}
	}

	return secInfos, nil
}
