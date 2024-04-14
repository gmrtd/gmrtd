package gmrtd

import "testing"

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
