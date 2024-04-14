package gmrtd

import "testing"

func TestNewCardSecurityNoData(t *testing.T) {
	if cardSec, err := NewCardSecurity(nil); cardSec != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if cardSec, err := NewCardSecurity([]byte{}); cardSec != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewCardSecurityUnhappyBadData(t *testing.T) {
	var cardSecurityFile []byte = HexToBytes("0608") // invalid data

	cardSecurity, err := NewCardSecurity(cardSecurityFile)

	if err == nil {
		t.Errorf("Error expected")
	}

	if cardSecurity != nil {
		t.Errorf("CardSecurity not expected for error case")
	}
}
