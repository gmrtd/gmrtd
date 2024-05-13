package gmrtd

import (
	"reflect"
	"testing"
)

func TestNewCardAccessHappyNoData(t *testing.T) {
	if cardAccess, err := NewCardAccess(nil); cardAccess != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if cardAccess, err := NewCardAccess([]byte{}); cardAccess != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewCardAccessUnhappyBadData(t *testing.T) {
	var cardAccessFile []byte = HexToBytes("0608") // invalid data

	cardAccess, err := NewCardAccess(cardAccessFile)

	if err == nil {
		t.Errorf("Error expected")
	}

	if cardAccess != nil {
		t.Errorf("CardAccess not expected for error case")
	}
}

func TestNewCardAccessHappyAT(t *testing.T) {
	// AT
	var cardAccessFile []byte = HexToBytes("31143012060a04007f0007020204020202010202010d")

	expPaceInfos := []PaceInfo{
		PaceInfo{Protocol: oidPaceEcdhGmAesCbcCmac128, Version: 2, ParameterId: 13},
	}

	cardAccess, err := NewCardAccess(cardAccessFile)

	if err != nil {
		t.Errorf("Error not expected")
	}

	if cardAccess.SecurityInfos.TotalCnt != 1 {
		t.Errorf("1 SecInfo expected")
	}

	if !reflect.DeepEqual(cardAccess.SecurityInfos.PaceInfos, expPaceInfos) {
		t.Errorf("PaceInfos differ to expected")
	}

}

func TestNewCardAccessHappyDE(t *testing.T) {
	// DE
	var cardAccessFile []byte = HexToBytes("31283012060a04007f0007020204020202010202010d3012060a04007f0007020204060202010202010d")

	expPaceInfos := []PaceInfo{
		PaceInfo{Protocol: oidPaceEcdhGmAesCbcCmac128, Version: 2, ParameterId: 13},
		PaceInfo{Protocol: oidPaceEcdhCamAesCbcCmac128, Version: 2, ParameterId: 13},
	}

	cardAccess, err := NewCardAccess(cardAccessFile)

	if err != nil {
		t.Errorf("Error not expected")
	}

	if cardAccess.SecurityInfos.TotalCnt != 2 {
		t.Errorf("2 SecInfos expected")
	}

	if !reflect.DeepEqual(cardAccess.SecurityInfos.PaceInfos, expPaceInfos) {
		t.Errorf("PaceInfos differ to expected")
	}
}
