package gmrtd

import (
	"testing"
)

func TestNewDG16NoData(t *testing.T) {
	if dg16, err := NewDG16(nil); dg16 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if dg16, err := NewDG16([]byte{}); dg16 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewDG16UnhappyRootTag(t *testing.T) {
	var dg16bytes []byte = HexToBytes("01021234") // valid TLV but invalid DG16, as tag 70 is missing

	dg16, err := NewDG16(dg16bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg16 != nil {
		t.Errorf("DG16 not expected for error case")
	}
}
