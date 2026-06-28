package document

import (
	"encoding/json"
	"testing"

	"github.com/gmrtd/gmrtd/oid"
)

func TestVerifiedChipAuthStatus(t *testing.T) {
	testCases := []struct {
		desc    string
		session Session
		exp     ChipAuthStatus
	}{
		{
			desc:    "CA success + passive auth success",
			session: Session{ChipAuthResult: &ChipAuthResult{Success: true}, PassiveAuthResult: &PassiveAuthResult{Success: true, Sod: NewPassiveAuth(nil)}},
			exp:     CHIP_AUTH_STATUS_CA,
		},
		{
			desc:    "CA success + passive auth fail",
			session: Session{ChipAuthResult: &ChipAuthResult{Success: true}, PassiveAuthResult: &PassiveAuthResult{Success: false}},
			exp:     CHIP_AUTH_STATUS_NONE,
		},
		{
			desc:    "CA success + no passive auth",
			session: Session{ChipAuthResult: &ChipAuthResult{Success: true}},
			exp:     CHIP_AUTH_STATUS_NONE,
		},
		{
			desc:    "AA success + passive auth success",
			session: Session{ActiveAuthResult: &ActiveAuthResult{Success: true, Evidence: &ActiveAuthEvidence{Algorithm: oid.OidRsaEncryption}}, PassiveAuthResult: &PassiveAuthResult{Success: true, Sod: NewPassiveAuth(nil)}},
			exp:     CHIP_AUTH_STATUS_AA,
		},
		{
			desc:    "AA success + passive auth fail",
			session: Session{ActiveAuthResult: &ActiveAuthResult{Success: true, Evidence: &ActiveAuthEvidence{Algorithm: oid.OidRsaEncryption}}, PassiveAuthResult: &PassiveAuthResult{Success: false}},
			exp:     CHIP_AUTH_STATUS_NONE,
		},
		{
			desc: "PACE-CAM success + passive auth success + CardSec verified",
			session: Session{
				PaceCamResult:     &PaceCamResult{Success: true},
				PassiveAuthResult: &PassiveAuthResult{Success: true, Sod: NewPassiveAuth(nil), CardSec: NewPassiveAuth(nil)},
			},
			exp: CHIP_AUTH_STATUS_PACE_CAM,
		},
		{
			desc: "PACE-CAM success + passive auth success + no CardSec",
			session: Session{
				PaceCamResult:     &PaceCamResult{Success: true},
				PassiveAuthResult: &PassiveAuthResult{Success: true, Sod: NewPassiveAuth(nil)},
			},
			exp: CHIP_AUTH_STATUS_NONE,
		},
		{
			desc: "PACE-CAM success + passive auth fail",
			session: Session{
				PaceCamResult:     &PaceCamResult{Success: true},
				PassiveAuthResult: &PassiveAuthResult{Success: false},
			},
			exp: CHIP_AUTH_STATUS_NONE,
		},
		{
			desc: "AA + PACE-CAM success + passive auth success + no CardSec - AA takes priority (PACE-CAM CardSec gate bypassed)",
			session: Session{
				ActiveAuthResult:  &ActiveAuthResult{Success: true, Evidence: &ActiveAuthEvidence{Algorithm: oid.OidRsaEncryption}},
				PaceCamResult:     &PaceCamResult{Success: true},
				PassiveAuthResult: &PassiveAuthResult{Success: true, Sod: NewPassiveAuth(nil)},
			},
			exp: CHIP_AUTH_STATUS_AA,
		},
		{
			desc:    "no chip auth + passive auth success",
			session: Session{PassiveAuthResult: &PassiveAuthResult{Success: true, Sod: NewPassiveAuth(nil)}},
			exp:     CHIP_AUTH_STATUS_NONE,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			act := tc.session.VerifiedChipAuthStatus()
			if tc.exp != act {
				t.Errorf("VerifiedChipAuthStatus [Act] %d [Exp] %d", act, tc.exp)
			}
		})
	}
}

func TestSession(t *testing.T) {
	testCases := []struct {
		session                   Session
		expChipAuthProtocolStatus ChipAuthStatus
	}{
		{
			// empty session
			session:           Session{},
			expChipAuthProtocolStatus: CHIP_AUTH_STATUS_NONE,
		},
		{
			// BAC (success)
			session: Session{BacResult: &BacResult{
				Success: true},
			},
			expChipAuthProtocolStatus: CHIP_AUTH_STATUS_NONE,
		},
		{
			// PACE (success, no CAM)
			session: Session{PaceResult: &PaceResult{
				Success:     true,
				Oid:         oid.OidPaceEcdhGmAesCbcCmac256,
				ParameterId: 13},
			},
			expChipAuthProtocolStatus: CHIP_AUTH_STATUS_NONE,
		},
		{
			// PACE-CAM (failure)
			session: Session{PaceCamResult: &PaceCamResult{
				Success: false},
			},
			expChipAuthProtocolStatus: CHIP_AUTH_STATUS_NONE,
		},
		{
			// PACE-CAM (success)
			session: Session{PaceCamResult: &PaceCamResult{
				Success: true},
			},
			expChipAuthProtocolStatus: CHIP_AUTH_STATUS_PACE_CAM,
		},
		{
			// Chip-Auth (failure)
			session: Session{ChipAuthResult: &ChipAuthResult{
				Success: false},
			},
			expChipAuthProtocolStatus: CHIP_AUTH_STATUS_NONE,
		},
		{
			// Chip-Auth (success)
			session: Session{ChipAuthResult: &ChipAuthResult{
				Success: true},
			},
			expChipAuthProtocolStatus: CHIP_AUTH_STATUS_CA,
		},
		{
			// Active-Auth (failure)
			session: Session{ActiveAuthResult: &ActiveAuthResult{
				Success: false,
				Evidence: &ActiveAuthEvidence{
					Algorithm: oid.OidRsaEncryption,
					Nonce:     []byte{0x12, 0x34, 0x56},
					Signature: []byte{0xAB, 0xCD, 0xEF}}},
			},
			expChipAuthProtocolStatus: CHIP_AUTH_STATUS_NONE,
		},
		{
			// Active-Auth (success)
			session: Session{ActiveAuthResult: &ActiveAuthResult{
				Success: true,
				Evidence: &ActiveAuthEvidence{
					Algorithm: oid.OidRsaEncryption,
					Nonce:     []byte{0x12, 0x34, 0x56},
					Signature: []byte{0xAB, 0xCD, 0xEF}}},
			},
			expChipAuthProtocolStatus: CHIP_AUTH_STATUS_AA,
		},
		{
			// Active-Auth + Chip-Auth (both success) - AA takes priority
			session: Session{
				ActiveAuthResult: &ActiveAuthResult{
					Success: true,
					Evidence: &ActiveAuthEvidence{
						Algorithm: oid.OidRsaEncryption,
						Nonce:     []byte{0x12, 0x34, 0x56},
						Signature: []byte{0xAB, 0xCD, 0xEF}}},
				ChipAuthResult: &ChipAuthResult{Success: true},
			},
			expChipAuthProtocolStatus: CHIP_AUTH_STATUS_AA,
		},
		{
			// Active-Auth + PACE-CAM (both success) - AA takes priority
			session: Session{
				ActiveAuthResult: &ActiveAuthResult{
					Success: true,
					Evidence: &ActiveAuthEvidence{
						Algorithm: oid.OidRsaEncryption,
						Nonce:     []byte{0x12, 0x34, 0x56},
						Signature: []byte{0xAB, 0xCD, 0xEF}}},
				PaceCamResult: &PaceCamResult{Success: true},
			},
			expChipAuthProtocolStatus: CHIP_AUTH_STATUS_AA,
		},
	}
	for _, tc := range testCases {
		actChipAuthStatus := tc.session.ChipAuthProtocolStatus()
		if tc.expChipAuthProtocolStatus != actChipAuthStatus {
			t.Errorf("Incorrect ChipAuthProtocolStatus [Act] %d [Exp] %d", actChipAuthStatus, tc.expChipAuthProtocolStatus)
		}

		if (tc.expChipAuthProtocolStatus == CHIP_AUTH_STATUS_NONE && tc.session.ChipAuthProtocolCompleted()) ||
			(tc.expChipAuthProtocolStatus != CHIP_AUTH_STATUS_NONE && !tc.session.ChipAuthProtocolCompleted()) {
			t.Errorf("ChipAuthProtocolCompleted mismatch")
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
				Success:     true,
				Oid:         oid.OidPaceEcdhGmAesCbcCmac256,
				ParameterId: 13},
			expJson: "{\"success\":true,\"oid\":\"0.4.0.127.0.7.2.2.4.2.4\",\"parameterId\":13}",
		},
		{
			// PACE Evidence
			object: &PaceCamEvidence{
				PaceOid:     oid.OidPaceEcdhCamAesCbcCmac128,
				ParameterId: 13,
				Nonce:       []byte{0x01, 0x02},
				TermMapPri:  []byte{0x03},
				TermMapPub:  []byte{0x04},
				ChipMapPub:  []byte{0x05},
				TermKaPri:   []byte{0x06},
				TermKaPub:   []byte{0x07},
				ChipKaPub:   []byte{0x08},
				EcadIC:      []byte{0x09}},
			expJson: "{\"paceOid\":\"0.4.0.127.0.7.2.2.4.6.2\",\"parameterId\":13,\"nonce\":\"AQI=\",\"termMapPri\":\"Aw==\",\"termMapPub\":\"BA==\",\"chipMapPub\":\"BQ==\",\"termKaPri\":\"Bg==\",\"termKaPub\":\"Bw==\",\"chipKaPub\":\"CA==\",\"ecadIC\":\"CQ==\"}",
		},
		{
			// PACE-CAM Result with Evidence
			object: &PaceCamResult{
				Success: true,
				Evidence: &PaceCamEvidence{
					PaceOid:     oid.OidPaceEcdhCamAesCbcCmac128,
					ParameterId: 13,
					Nonce:       []byte{0x01},
					TermMapPri:  []byte{0x02},
					TermMapPub:  []byte{0x03},
					ChipMapPub:  []byte{0x04},
					TermKaPri:   []byte{0x05},
					TermKaPub:   []byte{0x06},
					ChipKaPub:   []byte{0x07},
					EcadIC:      []byte{0x08}}},
			expJson: "{\"success\":true,\"evidence\":{\"paceOid\":\"0.4.0.127.0.7.2.2.4.6.2\",\"parameterId\":13,\"nonce\":\"AQ==\",\"termMapPri\":\"Ag==\",\"termMapPub\":\"Aw==\",\"chipMapPub\":\"BA==\",\"termKaPri\":\"BQ==\",\"termKaPub\":\"Bg==\",\"chipKaPub\":\"Bw==\",\"ecadIC\":\"CA==\"}}",
		},
		{
			// Active-Auth Evidence
			object: &ActiveAuthEvidence{
				Algorithm: oid.OidRsaEncryption,
				Nonce:     []byte{0x12, 0x34, 0x56},
				Signature: []byte{0xAB, 0xCD, 0xEF}},
			expJson: "{\"algorithm\":\"1.2.840.113549.1.1.1\",\"nonce\":\"EjRW\",\"signature\":\"q83v\"}",
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
