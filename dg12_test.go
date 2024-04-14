package gmrtd

import "testing"

func TestNewDG12NoData(t *testing.T) {
	if dg12, err := NewDG12(nil); dg12 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if dg12, err := NewDG12([]byte{}); dg12 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewDG12UnhappyRootTag(t *testing.T) {
	var dg12bytes []byte = HexToBytes("01021234") // valid TLV but invalid DG12, as tag 6C is missing

	dg12, err := NewDG12(dg12bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg12 != nil {
		t.Errorf("DG12 not expected for error case")
	}
}
