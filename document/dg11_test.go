package document

import (
	"reflect"
	"testing"

	"github.com/gmrtd/gmrtd/mrz"
	"github.com/gmrtd/gmrtd/utils"
)

func TestNewDG11NoData(t *testing.T) {
	if dg11, err := NewDG11(nil); dg11 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if dg11, err := NewDG11([]byte{}); dg11 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
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

func TestNewDG11UnhappyRootTag(t *testing.T) {
	var dg11bytes []byte = utils.HexToBytes("01021234") // valid TLV but invalid DG11, as tag 6B is missing

	dg11, err := NewDG11(dg11bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg11 != nil {
		t.Errorf("DG11 not expected for error case")
	}
}

func TestNewDG11Happy(t *testing.T) {
	testCases := []struct {
		dg11bytes  []byte
		expDetails PersonDetails
	}{
		{
			// Note: 6B length changed from 63 to 60.. spec has bad TLV for sample DG11 data!
			dg11bytes:  utils.HexToBytes("6B605C0A5F0E5F115F425F125F135F0E0D534D4954483C3C4A4F484E3C4A5F110A414E59544F574E3C4D4E5F4217313233204D41504C452052443C414E59544F574E3C4D4E5F120B31363132353535313231325F130C54524156454C3C4147454E54"),
			expDetails: PersonDetails{NameOfHolder: mrz.MrzName{Primary: "SMITH", Secondary: "JOHN J"}, PlaceOfBirth: []string{"ANYTOWN", "MN"}, Address: []string{"123 MAPLE RD", "ANYTOWN", "MN"}, Telephone: "16125551212", Profession: "TRAVEL AGENT"},
		},
	}
	for _, tc := range testCases {
		var doc Document

		err := doc.NewDG(11, tc.dg11bytes)

		if err != nil {
			t.Errorf("Error not expected")
		}

		if doc.Mf.Lds1.Dg11 == nil {
			t.Errorf("DG11 expected")
			break
		}

		if !reflect.DeepEqual(doc.Mf.Lds1.Dg11.Details, tc.expDetails) {
			t.Errorf("DG11 PersonDetails differs to expected\n(Act:%+v)\n(Exp:%+v)", doc.Mf.Lds1.Dg11.Details, tc.expDetails)
		}
	}
}

func TestNewDG11China(t *testing.T) {
	testCases := []struct {
		dg11bytes  []byte
		expDetails PersonDetails
	}{
		{
			dg11bytes:  utils.HexToBytes("6B1B5C045F0E5F0F5F0E06E8B5B5E5BDAC5F0F095A48414F3C3C42494E"),
			expDetails: PersonDetails{NameOfHolder: mrz.MrzName{Primary: "赵彬", Secondary: ""}, OtherNames: []mrz.MrzName{mrz.MrzName{Primary: "ZHAO", Secondary: "BIN"}}},
		},
	}
	for _, tc := range testCases {
		var doc Document

		err := doc.NewDG(11, tc.dg11bytes)

		if err != nil {
			t.Errorf("Error not expected")
		}

		if doc.Mf.Lds1.Dg11 == nil {
			t.Errorf("DG11 expected")
			break
		}

		if !reflect.DeepEqual(doc.Mf.Lds1.Dg11.Details, tc.expDetails) {
			t.Errorf("DG11 PersonDetails differs to expected\n(Act:%+v)\n(Exp:%+v)", doc.Mf.Lds1.Dg11.Details, tc.expDetails)
		}
	}
}
