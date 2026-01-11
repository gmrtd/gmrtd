package document

import (
	"encoding/json"
	"testing"

	"github.com/gmrtd/gmrtd/oid"
)

func TestSession(t *testing.T) {
	testCases := []struct {
		session           Session
		expChipAuthStatus ChipAuthStatus
	}{
		{
			// empty session
			session:           Session{},
			expChipAuthStatus: CHIP_AUTH_STATUS_NONE,
		},
		{
			// BAC (success)
			session: Session{BacResult: &BacResult{
				Success: true},
			},
			expChipAuthStatus: CHIP_AUTH_STATUS_NONE,
		},
		{
			// PACE (failure)
			session: Session{PaceResult: &PaceResult{
				Success:           true,
				Oid:               oid.OidPaceEcdhGmAesCbcCmac256,
				ParameterId:       13,
				ChipAuthenticated: false},
			},
			expChipAuthStatus: CHIP_AUTH_STATUS_NONE,
		},
		{
			// PACE (success)
			session: Session{PaceResult: &PaceResult{
				Success:           true,
				Oid:               oid.OidPaceEcdhGmAesCbcCmac256,
				ParameterId:       13,
				ChipAuthenticated: false},
			},
			expChipAuthStatus: CHIP_AUTH_STATUS_NONE,
		},
		{
			// PACE-CAM (failure)
			session: Session{PaceResult: &PaceResult{
				Success:           false,
				Oid:               oid.OidPaceEcdhCamAesCbcCmac192,
				ParameterId:       14,
				ChipAuthenticated: true},
			},
			expChipAuthStatus: CHIP_AUTH_STATUS_NONE,
		},
		{
			// PACE-CAM (success)
			session: Session{PaceResult: &PaceResult{
				Success:           true,
				Oid:               oid.OidPaceEcdhCamAesCbcCmac192,
				ParameterId:       14,
				ChipAuthenticated: true},
			},
			expChipAuthStatus: CHIP_AUTH_STATUS_PACE_CAM,
		},
		{
			// Chip-Auth (failure)
			session: Session{ChipAuthResult: &ChipAuthResult{
				Success: false},
			},
			expChipAuthStatus: CHIP_AUTH_STATUS_NONE,
		},
		{
			// Chip-Auth (success)
			session: Session{ChipAuthResult: &ChipAuthResult{
				Success: true},
			},
			expChipAuthStatus: CHIP_AUTH_STATUS_CA,
		},
		{
			// Active-Auth (failure)
			session: Session{ActiveAuthResult: &ActiveAuthResult{
				Success:   false,
				Algorithm: oid.OidRsaEncryption,
				Nonce:     []byte{0x12, 0x34, 0x56},
				Signature: []byte{0xAB, 0xCD, 0xEF}},
			},
			expChipAuthStatus: CHIP_AUTH_STATUS_NONE,
		},
		{
			// Active-Auth (success)
			session: Session{ActiveAuthResult: &ActiveAuthResult{
				Success:   true,
				Algorithm: oid.OidRsaEncryption,
				Nonce:     []byte{0x12, 0x34, 0x56},
				Signature: []byte{0xAB, 0xCD, 0xEF}},
			},
			expChipAuthStatus: CHIP_AUTH_STATUS_AA,
		},
	}
	for _, tc := range testCases {
		actChipAuthStatus := tc.session.ChipAuthStatus()
		if tc.expChipAuthStatus != actChipAuthStatus {
			t.Errorf("Incorrect ChipAuthStatus [Act] %d [Exp] %d", actChipAuthStatus, tc.expChipAuthStatus)
		}

		if (tc.expChipAuthStatus == CHIP_AUTH_STATUS_NONE && tc.session.ChipAuthenticated()) ||
			(tc.expChipAuthStatus != CHIP_AUTH_STATUS_NONE && !tc.session.ChipAuthenticated()) {
			t.Errorf("ChipAuthenticated mismatch")
		}
	}
}

func TestSessionJson(t *testing.T) {
	testCases := []struct {
		object  any
		expJson string
	}{
		{
			// PACE (success)
			object: &PaceResult{
				Success:           true,
				Oid:               oid.OidPaceEcdhGmAesCbcCmac256,
				ParameterId:       13,
				ChipAuthenticated: false},
			expJson: "{\"success\":true,\"oid\":\"0.4.0.127.0.7.2.2.4.2.4\",\"parameterId\":13,\"chipAuthenticated\":false}",
		},
		{
			// Active-Auth (success)
			object: &ActiveAuthResult{
				Success:   true,
				Algorithm: oid.OidRsaEncryption,
				Nonce:     []byte{0x12, 0x34, 0x56},
				Signature: []byte{0xAB, 0xCD, 0xEF}},
			expJson: "{\"success\":true,\"algorithm\":\"1.2.840.113549.1.1.1\",\"nonce\":\"EjRW\",\"signature\":\"q83v\"}",
		},
	}
	for _, tc := range testCases {
		jsonStr, err := json.Marshal(tc.object)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		if string(jsonStr) != tc.expJson {
			t.Errorf("JSON differs to expected [Act] %s [Exp] %s", string(jsonStr), tc.expJson)
		}
	}
}
