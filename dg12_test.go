package gmrtd

import "testing"

func TestNewDG12NoData(t *testing.T) {
	if NewDG12(nil) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
	if NewDG12([]byte{}) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}
