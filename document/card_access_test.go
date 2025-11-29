package document

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

func TestNewCardAccessHappyNil(t *testing.T) {
	cardAccess, err := NewCardAccess(nil)

	if err != nil {
		t.Errorf("Unexpected Error")
	}

	if cardAccess != nil {
		t.Errorf("Unexpected CardAccess")
	}
}

func TestNewCardAccessHappyNoData(t *testing.T) {
	cardAccess, err := NewCardAccess([]byte{})

	if err != nil {
		t.Errorf("Unexpected Error")
	}

	if cardAccess != nil {
		t.Errorf("Unexpected CardAccess")
	}
}

func TestNewCardAccessUnhappyBadData(t *testing.T) {
	var cardAccessFile []byte = utils.HexToBytes("0608") // invalid data

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
	var cardAccessFile []byte = utils.HexToBytes("31143012060a04007f0007020204020202010202010d")

	expPaceInfos := []PaceInfo{
		{Raw: utils.HexToBytes("3012060a04007f0007020204020202010202010d"), Protocol: oid.OidPaceEcdhGmAesCbcCmac128, Version: 2, ParameterId: big.NewInt(13)},
	}

	cardAccess, err := NewCardAccess(cardAccessFile)

	if err != nil {
		t.Errorf("Error not expected")
	}

	if cardAccess.SecurityInfos.TotalCnt() != 1 {
		t.Errorf("1 SecInfo expected")
	}

	if !reflect.DeepEqual(cardAccess.SecurityInfos.PaceInfos, expPaceInfos) {
		t.Errorf("PaceInfos differ to expected")
	}

}

func TestNewCardAccessHappyDE(t *testing.T) {
	// DE
	var cardAccessFile []byte = utils.HexToBytes("31283012060a04007f0007020204020202010202010d3012060a04007f0007020204060202010202010d")

	expPaceInfos := []PaceInfo{
		{Raw: utils.HexToBytes("3012060a04007f0007020204020202010202010d"), Protocol: oid.OidPaceEcdhGmAesCbcCmac128, Version: 2, ParameterId: big.NewInt(13)},
		{Raw: utils.HexToBytes("3012060a04007f0007020204060202010202010d"), Protocol: oid.OidPaceEcdhCamAesCbcCmac128, Version: 2, ParameterId: big.NewInt(13)},
	}

	cardAccess, err := NewCardAccess(cardAccessFile)

	if err != nil {
		t.Errorf("Error not expected")
	}

	if cardAccess.SecurityInfos.TotalCnt() != 2 {
		t.Errorf("2 SecInfos expected")
	}

	if !reflect.DeepEqual(cardAccess.SecurityInfos.PaceInfos, expPaceInfos) {
		t.Errorf("PaceInfos differ to expected")
	}
}
