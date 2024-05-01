package gmrtd

import (
	"reflect"
	"testing"
)

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

// (9303p10) A.5 EF.DG11 ADDITIONAL PERSONAL DETAILS
//		** NB fixed issues in test data... e.g. 6B len (x63->x60), 5f12 len (xE->xB)
//
// ‘6B’ ‘60’
// 		‘5C’ ‘0A’ ‘5F0E’ ‘5F11’ ‘5F42’ ‘5F12’ ‘5F13’
// 		‘5F0E’ ‘0D’ SMITH<<JOHN<J								5F0E0D534D4954483C3C4A4F484E3C4A
// 		‘5F11’ ‘0A’ ANYTOWN<MN									5F110A414E59544F574E3C4D4E
// 		‘5F42’ ‘17’ 123 MAPLE RD<ANYTOWN<MN						5F4217313233204D41504C452052443C414E59544F574E3C4D4E
// 		‘5F12’ ‘0B’ 16125551212									5F120B3136313235353531323132
// 		‘5F13’ ‘0C’ TRAVEL<AGENT								5F130C54524156454C3C4147454E54

// TODO - spec says that some tags are mandatory based on others (e.g. Title if Profession is present)
//			- however the example in the spec (as above) has Profession (5F13), but not Title (5F14), so not sure how
//			  much we can really on this

func TestNewDG11Happy(t *testing.T) {
	// TODO - 6B length changed from 63 to 60.. spec has bad TLV for sample DG11 data!
	var dg11bytes []byte = HexToBytes("6B605C0A5F0E5F115F425F125F135F0E0D534D4954483C3C4A4F484E3C4A5F110A414E59544F574E3C4D4E5F4217313233204D41504C452052443C414E59544F574E3C4D4E5F120B31363132353535313231325F130C54524156454C3C4147454E54")

	var expDetails PersonDetails = PersonDetails{NameOfHolder: MrzName{Primary: "SMITH", Secondary: "JOHN J"}, PlaceOfBirth: []string{"ANYTOWN", "MN"}, Address: []string{"123 MAPLE RD", "ANYTOWN", "MN"}, Telephone: "16125551212", Profession: "TRAVEL AGENT"}

	dg11, err := NewDG11(dg11bytes)

	if err != nil {
		t.Errorf("Error not expected")
	}

	if dg11 == nil {
		t.Errorf("DG11 expected")
	}

	if !reflect.DeepEqual(dg11.Details, expDetails) {
		t.Errorf("DG11 PersonDetails differs to expected\n(Act:%+v)\n(Exp:%+v)", dg11.Details, expDetails)
	}
}
