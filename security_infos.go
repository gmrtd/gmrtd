package gmrtd

import (
	"encoding/asn1"
	"fmt"
	"log/slog"
	"math/big"
)

// PACEInfo
// IF OID is a child under... id_PACE_DH_GM | id_PACE_ECDH_GM | id_PACE_DH_IM | id_PACE_ECDH_IM | id_PACE_ECDH_CAM
func isPACEInfo(oid asn1.ObjectIdentifier) bool {
	return oidHasPrefix(oid, oidPaceDhGm) || oidHasPrefix(oid, oidPaceEcdhGm) || oidHasPrefix(oid, oidPaceDhIm) || oidHasPrefix(oid, oidPaceEcdhIm) || oidHasPrefix(oid, oidPaceEcdhCam)
}

// PACEDomainParameterInfo
// IF OID exactly matches... id_PACE_DH_GM | id_PACE_ECDH_GM | id_PACE_DH_IM | id_PACE_ECDH_IM | id_PACE_ECDH_CAM
func isPACEDomainParameterInfo(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidPaceDhGm) || oid.Equal(oidPaceEcdhGm) || oid.Equal(oidPaceDhIm) || oid.Equal(oidPaceEcdhIm) || oid.Equal(oidPaceEcdhCam)
}

// ActiveAuthenticationInfo
// IF OID exactly matches... id_icao_mrtd_security_aaProtocolObject
func isActiveAuthenticationInfo(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidIcaoMrtdSecurityAaProtocolObject)
}

// ChipAuthenticationInfo
// IF OID is a child under... id_PK_DH | id_PK_ECDH
// TODO - why does above comment indicate something different to what is in code?
func isChipAuthenticationInfo(oid asn1.ObjectIdentifier) bool {
	return oidHasPrefix(oid, oidCaDh) || oidHasPrefix(oid, oidCaEcdh)
}

// ChipAuthenticationPublicKeyInfo
// IF OID exactly matches... id_PK_DH or id_PK_ECDH
func isChipAuthenticationPublicKeyInfo(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidPkDh) || oid.Equal(oidPkEcdh)
}

// TerminalAuthenticationInfo
// If OID starts/matches... id_TA		(not clear from spec... seems to imply id_TA)
func isTerminalAuthenticationInfo(oid asn1.ObjectIdentifier) bool {
	return oidHasPrefix(oid, oidTa) || oid.Equal(oidTa) // TODO - looks like equal NOT prefix, but need to verify
}

// EFDIRInfo
// IF OID exactly matches... id_EFDIR
func isEFDIRInfo(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidEfDir)
}

type SecurityInfoOid struct {
	Raw      asn1.RawContent
	Protocol asn1.ObjectIdentifier `asn1:""`
}
type SecurityInfoOidSET []SecurityInfoOid

type PaceInfo struct {
	Protocol    asn1.ObjectIdentifier
	Version     int
	ParameterId *big.Int `asn1:"optional"` // nil if not present // TODO - should have tests to verify (others also)
}

type PaceDomainParameterInfo struct {
	Protocol        asn1.ObjectIdentifier
	DomainParameter AlgorithmIdentifier
	ParameterId     *big.Int `asn1:"optional"` // nil if not present
}

type ActiveAuthenticationInfo struct {
	Protocol           asn1.ObjectIdentifier
	Version            int
	SignatureAlgorithm asn1.ObjectIdentifier
}

type ChipAuthenticationInfo struct {
	Protocol asn1.ObjectIdentifier
	Version  int
	KeyId    *big.Int `asn1:"optional"`
}

type ChipAuthenticationPublicKeyInfo struct {
	Protocol                    asn1.ObjectIdentifier
	ChipAuthenticationPublicKey SubjectPublicKeyInfo
	KeyId                       *big.Int `asn1:"optional"` // nil if not present
}

type SubjectPublicKeyInfo struct {
	Algorithm        AlgorithmIdentifier
	SubjectPublicKey asn1.BitString // TODO - pace breaks if we change this!
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue //int `asn1:"optional"` // nil if not present
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
	TotalCnt             int
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
		oid := secInfoOids[i].Protocol
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
			// TODO - may want to record warning/error if OID is not one of the 8 supported (i.e. 4 DH, 4 ECDH)
			//			see 9303p11 - 6.2.3 Cryptographic Specifications
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

	secInfos.TotalCnt =
		len(secInfos.PaceInfos) +
			len(secInfos.PaceDomainParamInfos) +
			len(secInfos.ActiveAuthInfos) +
			len(secInfos.ChipAuthInfos) +
			len(secInfos.ChipAuthPubKeyInfos) +
			len(secInfos.TermAuthInfos) +
			len(secInfos.EfDirInfos) +
			len(secInfos.UnhandledInfos)

	//log.Printf("SecInfos:\n%+v", secInfos)

	return secInfos, nil
}
