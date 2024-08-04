package gmrtd

import (
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestNewDG13NoData(t *testing.T) {
	if dg13, err := NewDG13(nil); dg13 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if dg13, err := NewDG13([]byte{}); dg13 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewDG13UnhappyRootTag(t *testing.T) {
	var dg13bytes []byte = utils.HexToBytes("01021234") // valid TLV but invalid DG13, as tag 6D is missing

	dg13, err := NewDG13(dg13bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg13 != nil {
		t.Errorf("DG13 not expected for error case")
	}
}
