package gmrtd

import "testing"

func TestNewDG11NoData(t *testing.T) {
	if dg11, err := NewDG11(nil); dg11 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if dg11, err := NewDG11([]byte{}); dg11 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewDG11UnhappyRootTag(t *testing.T) {
	var dg11bytes []byte = HexToBytes("01021234") // valid TLV but invalid DG11, as tag 6B is missing

	dg11, err := NewDG11(dg11bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg11 != nil {
		t.Errorf("DG11 not expected for error case")
	}
}
