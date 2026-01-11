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

	Apdus []iso7816.ApduLog `json:"apdus,omitempty"`
}

// determines whether Chip Authentication has been performed based on PACE-CAM/CA/AA success (if applicable)
func (session Session) ChipAuthenticated() bool {
	var chipAuthStatus ChipAuthStatus = session.ChipAuthStatus()

	// prefer explicit whitelisting of success
	if chipAuthStatus == CHIP_AUTH_STATUS_AA ||
		chipAuthStatus == CHIP_AUTH_STATUS_CA ||
		chipAuthStatus == CHIP_AUTH_STATUS_PACE_CAM {
		return true
	}

	return false
}

func (session Session) ChipAuthStatus() (status ChipAuthStatus) {
	// PACE-CAM
	if session.PaceResult != nil && session.PaceResult.Success && session.PaceResult.ChipAuthenticated {
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

type ChipActivationRsp struct {
	Atr []byte `json:"atr,omitempty"`
	Ats []byte `json:"ats,omitempty"`
}

type BacResult struct {
	Success bool `json:"success"`
}

type PaceResult struct {
	Success           bool                  `json:"success"`
	Oid               asn1.ObjectIdentifier `json:"oid"`
	ParameterId       int                   `json:"parameterId"`
	ChipAuthenticated bool                  `json:"chipAuthenticated"`
}

func (result PaceResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Success           bool   `json:"success"`
		Oid               string `json:"oid"`
		ParameterId       int    `json:"parameterId"`
		ChipAuthenticated bool   `json:"chipAuthenticated"`
	}{
		Success:           result.Success,
		Oid:               result.Oid.String(),
		ParameterId:       result.ParameterId,
		ChipAuthenticated: result.ChipAuthenticated,
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

type ChipAuthResult struct {
	Success bool `json:"success"`
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
