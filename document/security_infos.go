package document

import (
	"encoding/asn1"
	"log"
	"log/slog"
	"math/big"

	cms "github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

// PACEInfo
// IF OID is a child under... id_PACE_DH_GM | id_PACE_ECDH_GM | id_PACE_DH_IM | id_PACE_ECDH_IM | id_PACE_ECDH_CAM
func isPACEInfo(theOid asn1.ObjectIdentifier) bool {
	return oid.OidHasPrefix(theOid, oid.OidPaceDhGm) ||
		oid.OidHasPrefix(theOid, oid.OidPaceEcdhGm) ||
		oid.OidHasPrefix(theOid, oid.OidPaceDhIm) ||
		oid.OidHasPrefix(theOid, oid.OidPaceEcdhIm) ||
		oid.OidHasPrefix(theOid, oid.OidPaceEcdhCam)
}

// PACEDomainParameterInfo
// IF OID exactly matches... id_PACE_DH_GM | id_PACE_ECDH_GM | id_PACE_DH_IM | id_PACE_ECDH_IM | id_PACE_ECDH_CAM
func isPACEDomainParameterInfo(theOid asn1.ObjectIdentifier) bool {
	return theOid.Equal(oid.OidPaceDhGm) ||
		theOid.Equal(oid.OidPaceEcdhGm) ||
		theOid.Equal(oid.OidPaceDhIm) ||
		theOid.Equal(oid.OidPaceEcdhIm) ||
		theOid.Equal(oid.OidPaceEcdhCam)
}

// ActiveAuthenticationInfo
// IF OID exactly matches... id_icao_mrtd_security_aaProtocolObject
func isActiveAuthenticationInfo(theOid asn1.ObjectIdentifier) bool {
	return theOid.Equal(oid.OidIcaoMrtdSecurityAaProtocolObject)
}

// ChipAuthenticationInfo
// IF OID is a child under... id_PK_DH | id_PK_ECDH
// TODO - why does above comment indicate something different to what is in code?
func isChipAuthenticationInfo(theOid asn1.ObjectIdentifier) bool {
	return oid.OidHasPrefix(theOid, oid.OidCaDh) ||
		oid.OidHasPrefix(theOid, oid.OidCaEcdh)
}

// ChipAuthenticationPublicKeyInfo
// IF OID exactly matches... id_PK_DH or id_PK_ECDH
func isChipAuthenticationPublicKeyInfo(theOid asn1.ObjectIdentifier) bool {
	return theOid.Equal(oid.OidPkDh) ||
		theOid.Equal(oid.OidPkEcdh)
}

// TerminalAuthenticationInfo
// If OID starts/matches... id_TA		(not clear from spec... seems to imply id_TA)
func isTerminalAuthenticationInfo(theOid asn1.ObjectIdentifier) bool {
	return oid.OidHasPrefix(theOid, oid.OidTa) ||
		theOid.Equal(oid.OidTa) // TODO - looks like equal NOT prefix, but need to verify
}

// EFDIRInfo
// IF OID exactly matches... id_EFDIR
func isEFDIRInfo(theOid asn1.ObjectIdentifier) bool {
	return theOid.Equal(oid.OidEfDir)
}

type SecurityInfoOid struct {
	Raw      asn1.RawContent
	Protocol asn1.ObjectIdentifier `asn1:""`
}
type SecurityInfoOidSET []SecurityInfoOid

type PaceInfo struct {
	Protocol    asn1.ObjectIdentifier
	Version     int
	ParameterId *big.Int `asn1:"optional"` // nil if not present
}

type PaceDomainParameterInfo struct {
	Protocol        asn1.ObjectIdentifier
	DomainParameter cms.AlgorithmIdentifier
	ParameterId     *big.Int `asn1:"optional"` // nil if not present
}

// TODO - what is using this?
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
	Raw                         asn1.RawContent
	Protocol                    asn1.ObjectIdentifier
	ChipAuthenticationPublicKey cms.SubjectPublicKeyInfo
	KeyId                       *big.Int `asn1:"optional"` // nil if not present
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

// TODO - currently fails if anything wrong... maybe we should be more tolerant, but record issues?
func DecodeSecurityInfos(secInfoData []byte) (secInfos *SecurityInfos, err error) {
	var secInfoOids SecurityInfoOidSET

	// decode OID headers (preserving raw-content)
	// we only read the OID, so we expect unparsed data to remain
	err = utils.ParseAsn1(secInfoData, true, &secInfoOids)
	if err != nil {
		return nil, err
	}

	secInfos = &SecurityInfos{}

	// TODO - inspect data and check.. e.g. expected OIDs / version / ...
	//			e.g. ActiveAuthenticationInfo Version must be 1

	// process each record, based on the record-type (derived from OID)
	for i := range secInfoOids {
		oid := secInfoOids[i].Protocol
		data := secInfoOids[i].Raw

		slog.Debug("parsing secInfo", "oid", oid, "tlv", tlv.TlvDecode(data))

		if isPACEInfo(oid) {
			var paceInfo PaceInfo
			err = utils.ParseAsn1(data, false, &paceInfo)
			if err != nil {
				return nil, err
			}

			// validation
			if paceInfo.Version != 2 {
				log.Panicf("PaceInfo version must be 2 (Version:%d)", paceInfo.Version)
			}

			secInfos.PaceInfos = append(secInfos.PaceInfos, paceInfo)
		} else if isPACEDomainParameterInfo(oid) {
			var paceDomainParamInfo PaceDomainParameterInfo
			err = utils.ParseAsn1(data, false, &paceDomainParamInfo)
			if err != nil {
				return nil, err
			}
			secInfos.PaceDomainParamInfos = append(secInfos.PaceDomainParamInfos, paceDomainParamInfo)
		} else if isActiveAuthenticationInfo(oid) {
			var activeAuthInfo ActiveAuthenticationInfo
			err = utils.ParseAsn1(data, false, &activeAuthInfo)
			if err != nil {
				return nil, err
			}
			secInfos.ActiveAuthInfos = append(secInfos.ActiveAuthInfos, activeAuthInfo)
		} else if isChipAuthenticationInfo(oid) {
			var chipAuthInfo ChipAuthenticationInfo
			err = utils.ParseAsn1(data, false, &chipAuthInfo)
			if err != nil {
				return nil, err
			}
			secInfos.ChipAuthInfos = append(secInfos.ChipAuthInfos, chipAuthInfo)
		} else if isChipAuthenticationPublicKeyInfo(oid) {
			var chipAuthPubKeyInfo ChipAuthenticationPublicKeyInfo
			err = utils.ParseAsn1(data, false, &chipAuthPubKeyInfo)
			if err != nil {
				return nil, err
			}
			secInfos.ChipAuthPubKeyInfos = append(secInfos.ChipAuthPubKeyInfos, chipAuthPubKeyInfo)
			// TODO - may want to record warning/error if OID is not one of the 8 supported (i.e. 4 DH, 4 ECDH)
			//			see 9303p11 - 6.2.3 Cryptographic Specifications
		} else if isTerminalAuthenticationInfo(oid) {
			var termAuthInfo TerminalAuthenticationInfo
			err = utils.ParseAsn1(data, false, &termAuthInfo)
			if err != nil {
				return nil, err
			}
			secInfos.TermAuthInfos = append(secInfos.TermAuthInfos, termAuthInfo)
		} else if isEFDIRInfo(oid) {
			var efDirInfo EFDirInfo
			err = utils.ParseAsn1(data, false, &efDirInfo)
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

	return secInfos, nil
}
