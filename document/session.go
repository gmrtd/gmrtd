package document

import (
	"encoding/asn1"
	"encoding/json"
	"fmt"

	"github.com/gmrtd/gmrtd/iso7816"
)

type Session struct {
	ChipActivationRsp *ChipActivationRsp `json:"chipActivationRsp,omitempty"`

	// BAC
	BacErr    error      `json:"bacErr,omitempty"`
	BacResult *BacResult `json:"bacResult,omitempty"`

	// PACE
	PaceErr    error       `json:"paceErr,omitempty"`
	PaceResult *PaceResult `json:"paceResult,omitempty"`

	// Chip Authentication
	ChipAuthErr    error           `json:"chipAuthErr,omitempty"`
	ChipAuthResult *ChipAuthResult `json:"chipAuthResult,omitempty"`

	// Active Authentication
	ActiveAuthErr    error             `json:"activeAuthErr,omitempty"`
	ActiveAuthResult *ActiveAuthResult `json:"activeAuthResult,omitempty"`

	// Passive Authentication
	PassiveAuthErr    error              `json:"passiveAuthErr,omitempty"`
	PassiveAuthResult *PassiveAuthResult `json:"passiveAuthResult,omitempty"`

	// Summary (generated from above data)
	Summary *DocumentSummary `json:"summary,omitempty"`

	ApduLog *iso7816.ApduLog `json:"apduLog,omitempty"`
}

// ChipAuthProtocolCompleted reports whether a chip authentication protocol (PACE-CAM/CA/AA)
// completed successfully. This reflects protocol outcome only — the public key used is
// chip-supplied and unverified. Do NOT use as an anti-cloning verdict; use
// VerifiedChipAuthStatus() which gates on passive authentication.
func (session Session) ChipAuthProtocolCompleted() bool {
	status := session.ChipAuthProtocolStatus()

	if status == CHIP_AUTH_STATUS_AA ||
		status == CHIP_AUTH_STATUS_CA ||
		status == CHIP_AUTH_STATUS_PACE_CAM {
		return true
	}

	return false
}

// ChipAuthProtocolStatus reports which chip authentication protocol completed successfully
// (PACE-CAM, CA, or AA). This reflects protocol outcome only — the public key used is
// chip-supplied and unverified. Do NOT use as an anti-cloning verdict; use
// VerifiedChipAuthStatus() which gates on passive authentication.
func (session Session) ChipAuthProtocolStatus() (status ChipAuthStatus) {
	// PACE-CAM
	if session.PaceResult != nil && session.PaceResult.Success && session.PaceResult.CamProtocolCompleted {
		return CHIP_AUTH_STATUS_PACE_CAM
	}

	// CA
	if session.ChipAuthResult != nil && session.ChipAuthResult.Success {
		return CHIP_AUTH_STATUS_CA
	}

	// AA
	if session.ActiveAuthResult != nil && session.ActiveAuthResult.Success {
		return CHIP_AUTH_STATUS_AA
	}

	return CHIP_AUTH_STATUS_NONE
}

// VerifiedChipAuthStatus reports chip authentication status only when the corresponding
// public key is bound to a CSCA-trusted passive authentication chain. Without this binding,
// CA/AA/PACE-CAM only prove the chip holds the private key matching a key it supplied itself,
// which a clone trivially satisfies with its own keypair.
//
// CA/AA: requires PassiveAuthResult.Success (SOD verified via CSCA, DG14/DG15 hashes match).
// PACE-CAM: additionally requires CardSecurity verification (PassiveAuthResult.CardSec != nil).
func (session Session) VerifiedChipAuthStatus() ChipAuthStatus {
	if session.PassiveAuthResult == nil || !session.PassiveAuthResult.Success {
		return CHIP_AUTH_STATUS_NONE
	}

	status := session.ChipAuthProtocolStatus()

	// PACE-CAM key comes from CardSecurity — require it was independently verified
	if status == CHIP_AUTH_STATUS_PACE_CAM && session.PassiveAuthResult.CardSec == nil {
		return CHIP_AUTH_STATUS_NONE
	}

	return status
}

type ChipActivationRsp struct {
	Atr []byte `json:"atr,omitempty"`
	Ats []byte `json:"ats,omitempty"`
}

type BacResult struct {
	Success bool `json:"success"`
}

type PaceResult struct {
	Success              bool                  `json:"success"`
	Oid                  asn1.ObjectIdentifier `json:"oid"`
	ParameterId          int                   `json:"parameterId"`
	CamProtocolCompleted bool                  `json:"camProtocolCompleted"`
}

func (result PaceResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Success              bool   `json:"success"`
		Oid                  string `json:"oid"`
		ParameterId          int    `json:"parameterId"`
		CamProtocolCompleted bool   `json:"camProtocolCompleted"`
	}{
		Success:              result.Success,
		Oid:                  result.Oid.String(),
		ParameterId:          result.ParameterId,
		CamProtocolCompleted: result.CamProtocolCompleted,
	})
}

type ActiveAuthResult struct {
	Success   bool                  `json:"success"`
	Algorithm asn1.ObjectIdentifier `json:"algorithm"`
	Nonce     []byte                `json:"nonce"`
	Signature []byte                `json:"signature"`
}

func (result ActiveAuthResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Success   bool   `json:"success"`
		Algorithm string `json:"algorithm"`
		Nonce     []byte `json:"nonce"`
		Signature []byte `json:"signature"`
	}{
		Success:   result.Success,
		Algorithm: result.Algorithm.String(),
		Nonce:     result.Nonce,
		Signature: result.Signature,
	})
}

// ChipAuthEvidence holds the ephemeral terminal keypair and the SM-encrypted RAPDU from
// the CA verification step. Together with the Document (which contains the chip's public
// key in DG14), this is sufficient for independent cryptographic re-verification.
//
// The ephemeral terminal private key is safe to include: it is generated fresh for each
// CA session and has no value afterwards — the terminal will use a new keypair on the next
// session. Including it enables the verifier to re-derive the shared secret and session
// keys, then verify the SM MAC on the RAPDU.
type ChipAuthEvidence struct {
	TermPri    []byte `json:"termPri,omitempty"`
	TermPubKey []byte `json:"termPubKey,omitempty"`
	SmRapdu    []byte `json:"smRapdu,omitempty"`
}

type ChipAuthResult struct {
	Success  bool              `json:"success"`
	Evidence *ChipAuthEvidence `json:"evidence,omitempty"`
}

type ChipAuthStatus int

// intentionally use explicit values instead of iota
const (
	CHIP_AUTH_STATUS_NONE     = 0
	CHIP_AUTH_STATUS_PACE_CAM = 1
	CHIP_AUTH_STATUS_CA       = 2
	CHIP_AUTH_STATUS_AA       = 3
)

func (cas ChipAuthStatus) String() string {
	switch cas {
	case CHIP_AUTH_STATUS_NONE:
		return "n/a"
	case CHIP_AUTH_STATUS_PACE_CAM:
		return "PACE-CAM"
	case CHIP_AUTH_STATUS_CA:
		return "Chip Authentication"
	case CHIP_AUTH_STATUS_AA:
		return "Active Authentication"
	}

	return fmt.Sprintf("*UnsupportedValue* (cas:%d)", int(cas))
}

type PassiveAuthResult struct {
	Success bool         `json:"success"`
	Sod     *PassiveAuth `json:"sod,omitempty"`
	CardSec *PassiveAuth `json:"cardSec,omitempty"`
}

type PassiveAuth struct {
	CertChain [][]byte `json:"certChain,omitempty"`
}

func NewPassiveAuth(certChain [][]byte) *PassiveAuth {
	return &PassiveAuth{CertChain: certChain}
}

type DocumentSummary struct {
	DataTrusted      bool           `json:"dataTrusted"`
	ChipAuthenticity ChipAuthStatus `json:"chipAuthenticity"`
	LdsVersion       string         `json:"ldsVersion,omitempty"`
	UnicodeVersion   string         `json:"unicodeVersion,omitempty"`
}
