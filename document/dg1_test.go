package document

import (
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

func TestNewDG1NoData(t *testing.T) {
	if dg1, err := NewDG1(nil); dg1 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if dg1, err := NewDG1([]byte{}); dg1 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewDG1BadTlv(t *testing.T) {
	var dg1bytes []byte = utils.HexToBytes("02101234") // invalid TLV encoding - insufficient bytes

	dg1, err := NewDG1(dg1bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg1 != nil {
		t.Errorf("DG not expected for error case")
	}
}

func TestNewDG1UnhappyRootTag(t *testing.T) {
	var dg1bytes []byte = utils.HexToBytes("01021234") // valid TLV but invalid DG1, as tag 61 is missing

	dg1, err := NewDG1(dg1bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg1 != nil {
		t.Errorf("DG1 not expected for error case")
	}
}

func TestNewDG1UnhappyTag5F1F(t *testing.T) {
	var dg1bytes []byte = utils.HexToBytes("6109010212340203123456") // valid TLV but invalid DG1, as tag 5F1F is missing (under root)

	dg1, err := NewDG1(dg1bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg1 != nil {
		t.Errorf("DG1 not expected for error case")
	}
}

func TestNewDG1(t *testing.T) {
	testCases := []struct {
		dg1  []byte
		mrzi string
	}{
		{
			// based on sample TD2 MRZ:
			//		I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<6
			dg1:  utils.HexToBytes("614B5F1F48493C55544F4552494B53534F4E3C3C414E4E413C4D415249413C3C3C3C3C3C3C3C3C3C3C4432333134353839303755544F3734303831323246313230343135393C3C3C3C3C3C3C36"),
			mrzi: "D23145890774081221204159",
		},
		{
			// TD3 sample with missing 'optional data' and unset checkdigit (as seen on AT passport)
			// P<SURNAME<<FIRSTNAME<<<<<<<<<<<<<<<<<<<<<<<<DOCNUM<<<8UTO8201054M3401011<<<<<<<<<<<<<<<6
			dg1:  utils.HexToBytes("615b5f1f58503C5355524E414D453C3C46495253544E414D453C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C444F434E554D3C3C3C3855544F383230313035344D333430313031313C3C3C3C3C3C3C3C3C3C3C3C3C3C3C36"),
			mrzi: "DOCNUM<<<882010543401011",
		},
	}
	for _, tc := range testCases {
		var doc Document

		// parse DG1 data
		err := doc.NewDG(1, tc.dg1)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		// generate MRZi (as a quick way of verifying)
		actMrzi, err := doc.Mf.Lds1.Dg1.Mrz.EncodeMrzi()
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		if actMrzi != tc.mrzi {
			t.Errorf("DG1 MRZi mismatch (Exp:%s, Act:%s)", tc.mrzi, actMrzi)
		}
	}
}

func TestNewDG1UnhappyBadMRZ(t *testing.T) {
	// based on sample TD2 MRZ:
	//		I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<6
	//
	// but with one byte appended (0x11) to result in invalid length
	dg1bytes := utils.HexToBytes("614C5F1F49493C55544F4552494B53534F4E3C3C414E4E413C4D415249413C3C3C3C3C3C3C3C3C3C3C4432333134353839303755544F3734303831323246313230343135393C3C3C3C3C3C3C3611")

	dg1, err := NewDG1(dg1bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg1 != nil {
		t.Errorf("DG1 not expected for error case")
	}
}

func TestGetIssuingCountryAlpha2(t *testing.T) {
	// test the country-code conversion from a fake DG1(MRZ)
	testCases := []struct {
		dg1Mrz          string
		expCountryCode2 string
	}{
		{
			// AT
			dg1Mrz:          "P<AUTDOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<D123456785UTO6508092M3505207<<<<<<<<<<<<<<<0",
			expCountryCode2: "AT",
		},
		{
			// DE
			// note: this is the main test, as germany uses a historical 1-character country-code (D)
			dg1Mrz:          "P<D<<DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<D123456785UTO6508092M3505207<<<<<<<<<<<<<<<0",
			expCountryCode2: "DE",
		},
		{
			// FI
			dg1Mrz:          "P<FINDOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<D123456785UTO6508092M3505207<<<<<<<<<<<<<<<0",
			expCountryCode2: "FI",
		},
		{
			// FR
			dg1Mrz:          "P<FRADOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<D123456785UTO6508092M3505207<<<<<<<<<<<<<<<0",
			expCountryCode2: "FR",
		},
		{
			// ID
			dg1Mrz:          "P<IDNDOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<D123456785UTO6508092M3505207<<<<<<<<<<<<<<<0",
			expCountryCode2: "ID",
		},
		{
			// MY
			dg1Mrz:          "P<MYSDOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<D123456785UTO6508092M3505207<<<<<<<<<<<<<<<0",
			expCountryCode2: "MY",
		},
		{
			// NZ
			dg1Mrz:          "P<NZLDOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<D123456785UTO6508092M3505207<<<<<<<<<<<<<<<0",
			expCountryCode2: "NZ",
		},
		{
			// PH
			dg1Mrz:          "P<PHLDOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<D123456785UTO6508092M3505207<<<<<<<<<<<<<<<0",
			expCountryCode2: "PH",
		},
		{
			// RU
			dg1Mrz:          "P<RUSDOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<D123456785UTO6508092M3505207<<<<<<<<<<<<<<<0",
			expCountryCode2: "RU",
		},
		{
			// SG
			dg1Mrz:          "P<SGPDOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<D123456785UTO6508092M3505207<<<<<<<<<<<<<<<0",
			expCountryCode2: "SG",
		},
		{
			// UK
			dg1Mrz:          "P<GBRDOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<D123456785UTO6508092M3505207<<<<<<<<<<<<<<<0",
			expCountryCode2: "GB",
		},
		{
			// US
			dg1Mrz:          "P<USADOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<D123456785UTO6508092M3505207<<<<<<<<<<<<<<<0",
			expCountryCode2: "US",
		},
	}
	for _, tc := range testCases {
		var err error
		var dg1 *DG1

		// build DG1 from MRZ
		{
			dg1Bytes := tlv.NewTlvConstructedNode(0x61).AddChild(tlv.NewTlvSimpleNode(0x5f1f, []byte(tc.dg1Mrz))).Encode()

			dg1, err = NewDG1(dg1Bytes)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
		}

		countryCode2, err := dg1.GetIssuingCountryAlpha2()
		if err != nil {
			t.Fatalf("GetIssuingCountryAlpha2 error: %s", err)
		}

		if !strings.EqualFold(tc.expCountryCode2, countryCode2) {
			t.Fatalf("countryCode differs to expected (exp:%s, act:%s)", tc.expCountryCode2, countryCode2)
		}
	}

}

func TestGetIssuingCountryAlpha2ErrorNoMrz(t *testing.T) {
	var dg1 DG1

	_, err := dg1.GetIssuingCountryAlpha2()
	if err == nil {
		t.Fatalf("Expected error")
	}
}

func TestGetIssuingCountryAlpha2ErrorBadCountry(t *testing.T) {
	// MRZ country changed to a fake country (XYZ) to trigger country-code conversion (3->2 letter) error
	var err error
	var mrz string = "P<XYZDOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<D123456785UTO6508092M3505207<<<<<<<<<<<<<<<0"
	var dg1 *DG1

	// build DG1 from MRZ
	{
		dg1Bytes := tlv.NewTlvConstructedNode(0x61).AddChild(tlv.NewTlvSimpleNode(0x5f1f, []byte(mrz))).Encode()

		dg1, err = NewDG1(dg1Bytes)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
	}

	_, err = dg1.GetIssuingCountryAlpha2()
	if err == nil {
		t.Fatalf("Expected error")
	}
}
