package gmrtd

import (
	"testing"
)

func TestNewDG15NoData(t *testing.T) {
	if NewDG15(nil) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
	if NewDG15([]byte{}) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

