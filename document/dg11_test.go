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

func TestNewDG11BadTlv(t *testing.T) {
	var dg11bytes []byte = utils.HexToBytes("02101234") // invalid TLV encoding - insufficient bytes

	dg11, err := NewDG11(dg11bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg11 != nil {
		t.Errorf("DG not expected for error case")
	}
}

func TestNewDG11BadTagsErr(t *testing.T) {
	var dg11bytes []byte = utils.HexToBytes("6B055C035F0E5F") // invalid Tags - 5F0E followed by partial tag 5F??

	dg11, err := NewDG11(dg11bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg11 != nil {
		t.Errorf("DG not expected for error case")
	}
}

func TestNewDG11UnknownTagErr(t *testing.T) {
	var dg11bytes []byte = utils.HexToBytes("6B045C025F00") // unknown tag 5F00

	dg11, err := NewDG11(dg11bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg11 != nil {
		t.Errorf("DG not expected for error case")
	}
}

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
			//
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
			dg11bytes:  utils.HexToBytes("6B605C0A5F0E5F115F425F125F135F0E0D534D4954483C3C4A4F484E3C4A5F110A414E59544F574E3C4D4E5F4217313233204D41504C452052443C414E59544F574E3C4D4E5F120B31363132353535313231325F130C54524156454C3C4147454E54"),
			expDetails: PersonDetails{NameOfHolder: &mrz.MrzName{Primary: "SMITH", Secondary: "JOHN J"}, PlaceOfBirth: []string{"ANYTOWN", "MN"}, Address: []string{"123 MAPLE RD", "ANYTOWN", "MN"}, Telephone: "16125551212", Profession: "TRAVEL AGENT"},
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
			expDetails: PersonDetails{NameOfHolder: &mrz.MrzName{Primary: "赵彬", Secondary: ""}, OtherNames: []mrz.MrzName{{Primary: "ZHAO", Secondary: "BIN"}}},
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

func TestNewDG11OtherNames(t *testing.T) {
	testCases := []struct {
		dg11bytes  []byte
		expError   bool
		expDetails PersonDetails
	}{
		{
			// Other Names (*2) - wrapped with A0 - referenced as 5F0F in tag-list [nominal case]
			dg11bytes:  utils.HexToBytes("6B245C025F0FA01E0201025F0F0B534D4954483C3C4A4F484E5F0F0A4A4F484E3C534D495448"),
			expDetails: PersonDetails{OtherNames: []mrz.MrzName{{Primary: "SMITH", Secondary: "JOHN"}, {Primary: "JOHN SMITH"}}},
		},
		{
			// Other Names (*2) - wrapped with A0 - referenced as *A0* in tag-list [deviation - e.g. Belarus ID]
			dg11bytes:  utils.HexToBytes("6B235C01A0A01E0201025F0F0B534D4954483C3C4A4F484E5F0F0A4A4F484E3C534D495448"),
			expDetails: PersonDetails{OtherNames: []mrz.MrzName{{Primary: "SMITH", Secondary: "JOHN"}, {Primary: "JOHN SMITH"}}},
		},
		{
			// Other Names (*1) - *NOT* wrapped with A0 - referenced as 5F0F in tag-list [deviation - e.g. China passport]
			dg11bytes:  utils.HexToBytes("6B125C025F0F5F0F0B534D4954483C3C4A4F484E"),
			expDetails: PersonDetails{OtherNames: []mrz.MrzName{{Primary: "SMITH", Secondary: "JOHN"}}},
		},
		{
			// *ERROR*
			// Other Names (*1) - wrapped with A0 - referenced as 5F0F in tag-list [nominal]
			// ** BUT with incorrectly encoded MRZ Name that has 3 components (instead of 1 or 2)
			dg11bytes: utils.HexToBytes("6B1E5C025F0FA0180201015F0F12534D4954483C3C534D4954483C3C4A4F484E"),
			expError:  true,
		},
	}
	for _, tc := range testCases {
		var doc Document

		err := doc.NewDG(11, tc.dg11bytes)

		if tc.expError {
			/*
			* expect error
			 */
			if err == nil {
				t.Errorf("Error expected")
			}
		} else {
			/*
			* expect success
			 */
			if err != nil {
				t.Errorf("Error not expected (%s)", err)
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
}
