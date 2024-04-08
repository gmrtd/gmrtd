package gmrtd

import (
	"testing"
)

func TestNewDG16NoData(t *testing.T) {
	if NewDG16(nil) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
	if NewDG16([]byte{}) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

