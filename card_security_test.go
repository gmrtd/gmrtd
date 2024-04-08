package gmrtd

import "testing"

func TestNewCardSecurityNoData(t *testing.T) {
	if NewCardSecurity(nil) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
	if NewCardSecurity([]byte{}) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}
