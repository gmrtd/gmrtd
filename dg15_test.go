package gmrtd

import (
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestNewDG15NoData(t *testing.T) {
	if dg15, err := NewDG15(nil); dg15 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if dg15, err := NewDG15([]byte{}); dg15 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewDG15UnhappyRootTag(t *testing.T) {
	var dg15bytes []byte = utils.HexToBytes("01021234") // valid TLV but invalid DG15, as tag 6F is missing

	dg15, err := NewDG15(dg15bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg15 != nil {
		t.Errorf("DG15 not expected for error case")
	}
}
