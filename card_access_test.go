package gmrtd

import "testing"

func TestNewCardAccessNoData(t *testing.T) {
	if NewCardAccess(nil) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
	if NewCardAccess([]byte{}) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}
