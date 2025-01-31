package document

import (
	"bytes"
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
// IF OID is a child under... id-CA-DH or id-CA-ECDH
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
// If OID starts/matches... id_TA
func isTerminalAuthenticationInfo(theOid asn1.ObjectIdentifier) bool {
	return oid.OidHasPrefix(theOid, oid.OidTa) ||
		theOid.Equal(oid.OidTa) || oid.OidHasPrefix(theOid, oid.OidTa)
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
	Raw         asn1.RawContent
	Protocol    asn1.ObjectIdentifier
	Version     int
	ParameterId *big.Int `asn1:"optional"` // nil if not present
}

type PaceDomainParameterInfo struct {
	Raw             asn1.RawContent
	Protocol        asn1.ObjectIdentifier
	DomainParameter cms.AlgorithmIdentifier
	ParameterId     *big.Int `asn1:"optional"` // nil if not present
}

// TODO - what is using this?
type ActiveAuthenticationInfo struct {
	Raw                asn1.RawContent
	Protocol           asn1.ObjectIdentifier
	Version            int
	SignatureAlgorithm asn1.ObjectIdentifier
}

type ChipAuthenticationInfo struct {
	Raw      asn1.RawContent
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
	Raw      asn1.RawContent
	Protocol asn1.ObjectIdentifier
	Version  int
}

type EFDirInfo struct {
	Raw      asn1.RawContent
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
	Raw      asn1.RawContent
	Protocol asn1.ObjectIdentifier
}

/*
* Security Info handlers
 */

// returns true if handled, false otherwise, may also return an error
func handlePaceInfo(oid asn1.ObjectIdentifier, data []byte, secInfos *SecurityInfos) (handled bool, err error) {
	if !isPACEInfo(oid) {
		return false, nil
	}

	var paceInfo PaceInfo
	err = utils.ParseAsn1(data, false, &paceInfo)
	if err != nil {
		return false, err
	}

	// validation
	if paceInfo.Version != 2 {
		log.Panicf("PaceInfo version must be 2 (Version:%d)", paceInfo.Version)
	}

	secInfos.PaceInfos = append(secInfos.PaceInfos, paceInfo)

	return true, nil
}

// returns true if handled, false otherwise, may also return an error
func handlePaceDomainParameterInfo(oid asn1.ObjectIdentifier, data []byte, secInfos *SecurityInfos) (handled bool, err error) {
	if !isPACEDomainParameterInfo(oid) {
		return false, nil
	}

	var paceDomainParamInfo PaceDomainParameterInfo

	err = utils.ParseAsn1(data, false, &paceDomainParamInfo)
	if err != nil {
		return false, err
	}

	secInfos.PaceDomainParamInfos = append(secInfos.PaceDomainParamInfos, paceDomainParamInfo)

	return true, nil
}

// returns true if handled, false otherwise, may also return an error
func handleActiveAuthenticationInfo(oid asn1.ObjectIdentifier, data []byte, secInfos *SecurityInfos) (handled bool, err error) {
	if !isActiveAuthenticationInfo(oid) {
		return false, nil
	}

	var activeAuthInfo ActiveAuthenticationInfo

	err = utils.ParseAsn1(data, false, &activeAuthInfo)
	if err != nil {
		return false, err
	}

	secInfos.ActiveAuthInfos = append(secInfos.ActiveAuthInfos, activeAuthInfo)

	return true, nil
}

// returns true if handled, false otherwise, may also return an error
func handleChipAuthenticationInfo(oid asn1.ObjectIdentifier, data []byte, secInfos *SecurityInfos) (handled bool, err error) {
	if !isChipAuthenticationInfo(oid) {
		return false, nil
	}

	var chipAuthInfo ChipAuthenticationInfo

	err = utils.ParseAsn1(data, false, &chipAuthInfo)
	if err != nil {
		return false, err
	}

	secInfos.ChipAuthInfos = append(secInfos.ChipAuthInfos, chipAuthInfo)

	return true, nil
}

// returns true if handled, false otherwise, may also return an error
func handleChipAuthenticationPublicKeyInfo(oid asn1.ObjectIdentifier, data []byte, secInfos *SecurityInfos) (handled bool, err error) {
	if !isChipAuthenticationPublicKeyInfo(oid) {
		return false, nil
	}

	var chipAuthPubKeyInfo ChipAuthenticationPublicKeyInfo

	err = utils.ParseAsn1(data, false, &chipAuthPubKeyInfo)
	if err != nil {
		return false, err
	}

	secInfos.ChipAuthPubKeyInfos = append(secInfos.ChipAuthPubKeyInfos, chipAuthPubKeyInfo)
	// TODO - may want to record warning/error if OID is not one of the 8 supported (i.e. 4 DH, 4 ECDH)
	//			see 9303p11 - 6.2.3 Cryptographic Specifications

	return true, nil
}

// returns true if handled, false otherwise, may also return an error
func handleTerminalAuthenticationInfo(oid asn1.ObjectIdentifier, data []byte, secInfos *SecurityInfos) (handled bool, err error) {
	if !isTerminalAuthenticationInfo(oid) {
		return false, nil
	}

	var termAuthInfo TerminalAuthenticationInfo

	err = utils.ParseAsn1(data, false, &termAuthInfo)
	if err != nil {
		return false, err
	}

	secInfos.TermAuthInfos = append(secInfos.TermAuthInfos, termAuthInfo)

	return true, nil
}

// returns true if handled, false otherwise, may also return an error
func handleEfDirInfo(oid asn1.ObjectIdentifier, data []byte, secInfos *SecurityInfos) (handled bool, err error) {
	if !isEFDIRInfo(oid) {
		return false, nil
	}

	var efDirInfo EFDirInfo

	err = utils.ParseAsn1(data, false, &efDirInfo)
	if err != nil {
		return false, err
	}

	secInfos.EfDirInfos = append(secInfos.EfDirInfos, efDirInfo)

	return true, nil
}

// returns true (as will always handle the data)
// NB should be called after all other handlers
func handleUnsupportedInfo(oid asn1.ObjectIdentifier, data []byte, secInfos *SecurityInfos) (handled bool, err error) {
	var unhandledInfo UnhandledInfo

	// NB isPartiallyParsed=TRUE because we expect data after the Protocol(OID)
	err = utils.ParseAsn1(data, true, &unhandledInfo)
	if err != nil {
		return false, err
	}

	secInfos.UnhandledInfos = append(secInfos.UnhandledInfos, unhandledInfo)
	return true, nil
}

/*
* Security Info handlers configuration
 */

type SecurityInfoHandlerFn func(asn1.ObjectIdentifier, []byte, *SecurityInfos) (bool, error)

var securityInfoHandleFnArr []SecurityInfoHandlerFn = []SecurityInfoHandlerFn{
	handlePaceInfo,
	handlePaceDomainParameterInfo,
	handleActiveAuthenticationInfo,
	handleChipAuthenticationInfo,
	handleChipAuthenticationPublicKeyInfo,
	handleTerminalAuthenticationInfo,
	handleEfDirInfo,
	handleUnsupportedInfo,
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

		slog.Debug("parsing secInfo", "oid", oid, "tlv", tlv.Decode(data))

		var handled bool = false

		for _, handleFn := range securityInfoHandleFnArr {
			handled, err = handleFn(oid, data, secInfos)
			if err != nil {
				return nil, err
			}
			if handled {
				break
			}
		}

		if !handled {
			panic("secInfo should have been handled by at least one of the handlers (e.g. handleUnsupportedInfo)")
		}
	}

	return secInfos, nil
}

// determines whether the 'paceInfos' are present within the 'secInfos'
func (secInfos *SecurityInfos) ContainsPaceInfos(paceInfos []PaceInfo) bool {
	for _, paceInfo := range paceInfos {
		var isPresent bool = false
		for i := range secInfos.PaceInfos {
			if bytes.Equal(paceInfo.Raw, secInfos.PaceInfos[i].Raw) {
				isPresent = true
				break
			}
		}
		if !isPresent {
			slog.Warn("SecInfos.ContainsPaceInfos - does NOT contain SecInfo", "PaceInfo", paceInfo)
			return false
		}
	}
	return true
}

// determines whether the 'paceDomainParamerInfos' are present within the 'secInfos'
func (secInfos *SecurityInfos) ContainsPaceDomainParameterInfos(paceDomainParamerInfos []PaceDomainParameterInfo) bool {
	for _, paceDomainParameterInfo := range paceDomainParamerInfos {
		var isPresent bool = false
		for i := range secInfos.PaceDomainParamInfos {
			if bytes.Equal(paceDomainParameterInfo.Raw, secInfos.PaceDomainParamInfos[i].Raw) {
				isPresent = true
				break
			}
		}
		if !isPresent {
			slog.Warn("SecInfos.ContainsPaceDomainParameterInfos - does NOT contain SecInfo", "PaceDomainParameterInfo", paceDomainParameterInfo)
			return false
		}
	}
	return true
}

// determines whether the 'activeAuthInfos' are present within the 'secInfos'
func (secInfos *SecurityInfos) ContainsActiveAuthInfos(activeAuthInfos []ActiveAuthenticationInfo) bool {
	for _, activeAuthInfo := range activeAuthInfos {
		var isPresent bool = false
		for i := range secInfos.ActiveAuthInfos {
			if bytes.Equal(activeAuthInfo.Raw, secInfos.ActiveAuthInfos[i].Raw) {
				isPresent = true
				break
			}
		}
		if !isPresent {
			slog.Warn("SecInfos.ContainsActiveAuthInfos - does NOT contain SecInfo", "ActiveAuthenticationInfo", activeAuthInfo)
			return false
		}
	}
	return true
}

// determines whether the 'chipAuthInfos' are present within the 'secInfos'
func (secInfos *SecurityInfos) ContainsChipAuthInfos(chipAuthInfos []ChipAuthenticationInfo) bool {
	for _, chipAuthInfo := range chipAuthInfos {
		var isPresent bool = false
		for i := range secInfos.ChipAuthInfos {
			if bytes.Equal(chipAuthInfo.Raw, secInfos.ChipAuthInfos[i].Raw) {
				isPresent = true
				break
			}
		}
		if !isPresent {
			slog.Warn("SecInfos.ContainsChipAuthInfos - does NOT contain SecInfo", "ChipAuthenticationInfo", chipAuthInfo)
			return false
		}
	}
	return true
}

// determines whether the 'chipAuthPubKeyInfos' are present within the 'secInfos'
func (secInfos *SecurityInfos) ContainsChipAuthPubKeyInfos(chipAuthPubKeyInfos []ChipAuthenticationPublicKeyInfo) bool {
	for _, chipAuthPubKeyInfo := range chipAuthPubKeyInfos {
		var isPresent bool = false
		for i := range secInfos.ChipAuthPubKeyInfos {
			if bytes.Equal(chipAuthPubKeyInfo.Raw, secInfos.ChipAuthPubKeyInfos[i].Raw) {
				isPresent = true
				break
			}
		}
		if !isPresent {
			slog.Warn("SecInfos.ContainsChipAuthPubKeyInfos - does NOT contain SecInfo", "ChipAuthenticationPublicKeyInfo", chipAuthPubKeyInfo)
			return false
		}
	}
	return true
}

// determines whether the 'termAuthInfos' are present within the 'secInfos'
func (secInfos *SecurityInfos) ContainsTermAuthInfos(termAuthInfos []TerminalAuthenticationInfo) bool {
	for _, termAuthInfo := range termAuthInfos {
		var isPresent bool = false
		for i := range secInfos.TermAuthInfos {
			if bytes.Equal(termAuthInfo.Raw, secInfos.TermAuthInfos[i].Raw) {
				isPresent = true
				break
			}
		}
		if !isPresent {
			slog.Warn("SecInfos.ContainsTermAuthInfos - does NOT contain SecInfo", "TerminalAuthenticationInfo", termAuthInfo)
			return false
		}
	}
	return true
}

// determines whether the 'efDirInfos' are present within the 'secInfos'
func (secInfos *SecurityInfos) ContainsEfDirInfos(efDirInfos []EFDirInfo) bool {
	for _, efDirInfo := range efDirInfos {
		var isPresent bool = false
		for i := range secInfos.EfDirInfos {
			if bytes.Equal(efDirInfo.Raw, secInfos.EfDirInfos[i].Raw) {
				isPresent = true
				break
			}
		}
		if !isPresent {
			slog.Warn("SecInfos.ContainsEfDirInfos - does NOT contain SecInfo", "EFDirInfo", efDirInfo)
			return false
		}
	}
	return true
}

// determines whether the 'unhandledInfos' are present within the 'secInfos'
func (secInfos *SecurityInfos) ContainsUnhandledInfos(unhandledInfos []UnhandledInfo) bool {
	for _, unhandledInfo := range unhandledInfos {
		var isPresent bool = false
		for i := range secInfos.UnhandledInfos {
			if bytes.Equal(unhandledInfo.Raw, secInfos.UnhandledInfos[i].Raw) {
				isPresent = true
				break
			}
		}
		if !isPresent {
			slog.Warn("SecInfos.ContainsUnhandledInfos - does NOT contain SecInfo", "UnhandledInfo", unhandledInfo)
			return false
		}
	}
	return true
}

// evaluates whether 'secInfoSubset' exists within 'secInfo'
func (secInfos *SecurityInfos) Contains(secInfoSubset *SecurityInfos) bool {
	/*
	* Note: we also evaluate against 'unhandled' infos as these are technically
	*       records, even if we don't support them
	 */
	if secInfos.ContainsPaceInfos(secInfoSubset.PaceInfos) &&
		secInfos.ContainsPaceDomainParameterInfos(secInfoSubset.PaceDomainParamInfos) &&
		secInfos.ContainsActiveAuthInfos(secInfoSubset.ActiveAuthInfos) &&
		secInfos.ContainsChipAuthInfos(secInfoSubset.ChipAuthInfos) &&
		secInfos.ContainsChipAuthPubKeyInfos(secInfoSubset.ChipAuthPubKeyInfos) &&
		secInfos.ContainsTermAuthInfos(secInfoSubset.TermAuthInfos) &&
		secInfos.ContainsEfDirInfos(secInfoSubset.EfDirInfos) &&
		secInfos.ContainsUnhandledInfos(secInfoSubset.UnhandledInfos) {
		return true
	}

	return false
}

func (secInfos *SecurityInfos) GetTotalCnt() (cnt int) {
	cnt = 0
	cnt += len(secInfos.PaceInfos)
	cnt += len(secInfos.PaceDomainParamInfos)
	cnt += len(secInfos.ActiveAuthInfos)
	cnt += len(secInfos.ChipAuthInfos)
	cnt += len(secInfos.ChipAuthPubKeyInfos)
	cnt += len(secInfos.TermAuthInfos)
	cnt += len(secInfos.EfDirInfos)
	cnt += len(secInfos.UnhandledInfos)
	return cnt
}
