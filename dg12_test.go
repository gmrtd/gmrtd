package gmrtd

import (
	"reflect"
	"testing"
)

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

func TestNewDG12Happy(t *testing.T) {
	// Adapted from NZ passport (with data changed)
	//
	// 6C205C045F555F565F550E32303136313131353031333631325F56064E2D34393632
	//
	//	6c
	// 		5c: 5f555f56 [_U_V]
	// 		5f55: 3230313631313135303133363132 [20161115013612]
	// 		5f56: 4e2d34393632 [N-4962]

	var dg12bytes []byte = HexToBytes("6C205C045F555F565F550E32303136313131353031333631325F56064E2D34393632")

	var expDetails DocumentDetails = DocumentDetails{PersoDateTime: "20161115013612", PersoSystemSerialNumber: "N-4962"}

	var doc Document
	var err error

	err = doc.NewDG(12, dg12bytes)

	if err != nil {
		t.Errorf("Error not expected")
	}

	if doc.Dg12 == nil {
		t.Errorf("DG12 expected")
	}

	if !reflect.DeepEqual(doc.Dg12.Details, expDetails) {
		t.Errorf("DG12 DocumentDetails differs to expected\n(Act:%+v)\n(Exp:%+v)", doc.Dg12.Details, expDetails)
	}
}
