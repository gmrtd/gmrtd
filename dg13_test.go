package gmrtd

import (
	"testing"
)

func TestNewDG13NoData(t *testing.T) {
	if NewDG13(nil) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
	if NewDG13([]byte{}) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

