package gmrtd

import (
	"testing"
)

func TestFileNotFoundStatus(t *testing.T) {
	rApdu := RApdu{Status: 0x6A82}

	if !rApdu.FileNotFound() {
		t.Errorf("FileNotFound expected")
	}
}

func TestParseRApduNoData(t *testing.T) {
	_, err := ParseRApdu(nil)
	if err == nil {
		t.Errorf("Error expected when parsing no rApdu data (as min 2 bytes)")
	}
}
