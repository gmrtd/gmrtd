package document

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"

	cms "github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/oid"
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

func (p PaceInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Protocol    string   `json:"protocol,omitempty"`
		Version     int      `json:"version,omitempty"`
		ParameterId *big.Int `json:"parameterId,omitempty"`
	}{
		Protocol:    p.Protocol.String(),
		Version:     p.Version,
		ParameterId: p.ParameterId,
	})
}

// TODO - add JSON marshal (PaceDomainParameterInfo)
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

func (aa ActiveAuthenticationInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Protocol           string `json:"protocol,omitempty"`
		Version            int    `json:"version,omitempty"`
		SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`
	}{
		Protocol:           aa.Protocol.String(),
		Version:            aa.Version,
		SignatureAlgorithm: aa.SignatureAlgorithm.String(),
	})
}

type ChipAuthenticationInfo struct {
	Raw      asn1.RawContent
	Protocol asn1.ObjectIdentifier
	Version  int
	KeyId    *big.Int `asn1:"optional"`
}

func (ca ChipAuthenticationInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Protocol string   `json:"protocol,omitempty"`
		Version  int      `json:"version,omitempty"`
		KeyId    *big.Int `json:"keyId,omitempty"`
	}{
		Protocol: ca.Protocol.String(),
		Version:  ca.Version,
		KeyId:    ca.KeyId,
	})
}

type ChipAuthenticationPublicKeyInfo struct {
	Raw                         asn1.RawContent
	Protocol                    asn1.ObjectIdentifier
	ChipAuthenticationPublicKey cms.SubjectPublicKeyInfo
	KeyId                       *big.Int `asn1:"optional"` // nil if not present
}

func (capk ChipAuthenticationPublicKeyInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Protocol                    string                   `json:"protocol,omitempty"`
		ChipAuthenticationPublicKey cms.SubjectPublicKeyInfo `json:"chipAuthenticationPublicKey,omitempty"`
		KeyId                       *big.Int                 `json:"keyId,omitempty"`
	}{
		Protocol:                    capk.Protocol.String(),
		ChipAuthenticationPublicKey: capk.ChipAuthenticationPublicKey,
		KeyId:                       capk.KeyId,
	})
}

type TerminalAuthenticationInfo struct {
	Raw      asn1.RawContent
	Protocol asn1.ObjectIdentifier
	Version  int
}

func (ta TerminalAuthenticationInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Protocol string `json:"protocol,omitempty"`
		Version  int    `json:"version,omitempty"`
	}{
		Protocol: ta.Protocol.String(),
		Version:  ta.Version,
	})
}

type EFDirInfo struct {
	Raw      asn1.RawContent
	Protocol asn1.ObjectIdentifier
	EFDir    []byte
}

func (ef EFDirInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Protocol string `json:"protocol,omitempty"`
		EFDir    []byte `json:"efDir,omitempty"`
	}{
		Protocol: ef.Protocol.String(),
		EFDir:    ef.EFDir,
	})
}

type UnhandledInfo struct {
	Raw      asn1.RawContent       `json:"rawData,omitempty"`
	Protocol asn1.ObjectIdentifier `json:"protocol,omitempty"`
}

func (u UnhandledInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Protocol string `json:"protocol,omitempty"`
		Raw      []byte `json:"raw,omitempty"`
	}{
		Protocol: u.Protocol.String(),
		Raw:      u.Raw,
	})
}

type SecurityInfos struct {
	RawData              []byte                            `json:"rawData,omitempty"`
	PaceInfos            []PaceInfo                        `json:"paceInfos,omitempty"`
	PaceDomainParamInfos []PaceDomainParameterInfo         `json:"paceDomainParamInfos,omitempty"`
	ActiveAuthInfos      []ActiveAuthenticationInfo        `json:"activeAuthInfos,omitempty"`
	ChipAuthInfos        []ChipAuthenticationInfo          `json:"chipAuthInfos,omitempty"`
	ChipAuthPubKeyInfos  []ChipAuthenticationPublicKeyInfo `json:"chipAuthPubKeyInfos,omitempty"`
	TermAuthInfos        []TerminalAuthenticationInfo      `json:"termAuthInfos,omitempty"`
	EfDirInfos           []EFDirInfo                       `json:"efDirInfos,omitempty"`
	UnhandledInfos       []UnhandledInfo                   `json:"unhandledInfos,omitempty"`
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
		return false, fmt.Errorf("[handlePaceInfo] ParseAsn1 error: %w", err)
	}

	// validation
	// TODO - ideally we'd log this but not throw a hard error, we should
	//        also be consistent and do these checks for other record types
	if paceInfo.Version != 2 {
		return false, fmt.Errorf("[handlePaceInfo] PaceInfo version must be 2 (Version:%d) (Data:%x)", paceInfo.Version, data)
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
		return false, fmt.Errorf("[handlePaceDomainParameterInfo] ParseAsn1 error: %w", err)
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
		return false, fmt.Errorf("[handleActiveAuthenticationInfo] ParseAsn1 error: %w", err)
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
		return false, fmt.Errorf("[handleChipAuthenticationInfo] ParseAsn1 error: %w", err)
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
		return false, fmt.Errorf("[handleChipAuthenticationPublicKeyInfo] ParseAsn1 error: %w", err)
	}

	secInfos.ChipAuthPubKeyInfos = append(secInfos.ChipAuthPubKeyInfos, chipAuthPubKeyInfo)

	// TODO - may want to record warning/error if OID is not one of the 8 supported (i.e. 4 DH, 4 ECDH)
	//			see 9303p11 - 6.2.3 Cryptographic Specifications
	//			- if we do this, then we should also do in other places also

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
		return false, fmt.Errorf("[handleTerminalAuthenticationInfo] ParseAsn1 error: %w", err)
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
		return false, fmt.Errorf("[handleEfDirInfo] ParseAsn1 error: %w", err)
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
		return false, fmt.Errorf("[handleUnsupportedInfo] ParseAsn1 error: %w", err)
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

func DecodeSecurityInfos(secInfoData []byte) (secInfos *SecurityInfos, err error) {
	var secInfoOids SecurityInfoOidSET

	// decode OID headers (preserving raw-content)
	// we only read the OID, so we expect unparsed data to remain
	err = utils.ParseAsn1(secInfoData, true, &secInfoOids)
	if err != nil {
		return nil, fmt.Errorf("[DecodeSecurityInfos] ParseAsn1 error: %w", err)
	}

	secInfos = &SecurityInfos{}
	secInfos.RawData = bytes.Clone(secInfoData)

	// process each record, based on the record-type (derived from OID)
	for i := range secInfoOids {
		oid := secInfoOids[i].Protocol
		data := secInfoOids[i].Raw

		slog.Debug("parsing secInfo", "oid", oid, "data", utils.BytesToHex(data))

		var handled bool = false

		for _, handleFn := range securityInfoHandleFnArr {
			handled, err = handleFn(oid, data, secInfos)
			if err != nil {
				return nil, fmt.Errorf("[DecodeSecurityInfos] handleFn (oid:%s) error: %w", oid.String(), err)
			}
			if handled {
				break
			}
		}

		if !handled {
			return nil, fmt.Errorf("[DecodeSecurityInfos] secInfo should have been handled by at least one of the handlers")
		}
	}

	return secInfos, nil
}

// determines whether 'subsetSecInfos' is present within 'secInfos'
// NB uses a generic ASN1 approach to compare against opaque objects
// returns: nil if okay, otherwise error
func (secInfos *SecurityInfos) Contains(subsetSecInfos *SecurityInfos) error {
	var err error

	var tmpSecInfos SecurityInfoOidSET
	err = utils.ParseAsn1(secInfos.RawData, true, &tmpSecInfos)
	if err != nil {
		return fmt.Errorf("[SecInfos.Contains] ParseAsn1(main) error: %w", err)
	}

	var tmpSubsetSecInfos SecurityInfoOidSET
	err = utils.ParseAsn1(subsetSecInfos.RawData, true, &tmpSubsetSecInfos)
	if err != nil {
		return fmt.Errorf("[SecInfos.Contains] ParseAsn1(subset) error: %w", err)
	}

	for _, tmpSubsetSecInfo := range tmpSubsetSecInfos {
		var isPresent bool = false

		for _, tmpSecInfo := range tmpSecInfos {
			if bytes.Equal(tmpSubsetSecInfo.Raw, tmpSecInfo.Raw) {
				isPresent = true
				break
			}
		}

		if !isPresent {
			return fmt.Errorf("[SecInfos.Contains] does NOT contain SecInfo (oid:%s) (raw:%x)", tmpSubsetSecInfo.Protocol.String(), tmpSubsetSecInfo.Raw)
		}

	}

	return nil
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
