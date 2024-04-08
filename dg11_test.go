package gmrtd

import "testing"

func TestNewDG11NoData(t *testing.T) {
	if NewDG11(nil) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
	if NewDG11([]byte{}) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}
