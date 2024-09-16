package mrz

import (
	"reflect"
	"testing"
)

func TestEncodeValueBadParamsErr(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	// NB bad parameters where min-len > max-len (i.e. 5 > 3)
	encodeValue("Test", 5, 3)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestEncodeValueTruncateOk(t *testing.T) {
	var minLen int = 0
	var maxLen int = 41
	var value string = "This string is too long and will be truncated"
	var expValue string = "This<string<is<too<long<and<will<be<trunc"

	// NB bad parameters where min-len > max-len (i.e. 5 > 3)
	actValue := encodeValue(value, minLen, maxLen)

	if actValue != expValue {
		t.Errorf("encodeValue differs to expected (Exp:%s) (Act:%s)", expValue, actValue)
	}
}

func TestEncodeValueRightPadOk(t *testing.T) {
	var minLen int = 50
	var maxLen int = -1
	var value string = "This string is too long and will be right padded"
	var expValue string = "This<string<is<too<long<and<will<be<right<padded<<"

	// NB bad parameters where min-len > max-len (i.e. 5 > 3)
	actValue := encodeValue(value, minLen, maxLen)

	if actValue != expValue {
		t.Errorf("encodeValue differs to expected (Exp:%s) (Act:%s)", expValue, actValue)
	}
}

func TestMrzDecodeBadLengthErr(t *testing.T) {
	// NB valid MRZ has length of: 72/88/90
	//    so this is clearly invalid
	var badMrz = "BadMrz"

	_, err := MrzDecode(badMrz)

	if err == nil {
		t.Errorf("Error expected")
	}
}

func TestCalcCheckdigit(t *testing.T) {
	testCases := []struct {
		data          string
		expCheckDigit int
	}{
		{
			// TD1
			data:          "D231458907<<<<<<<<<<<<<<<34071279507122<<<<<<<<<<<",
			expCheckDigit: 2,
		},
		{
			// TD2 sample
			data:          "HA672242<658022549601086<<<<<<<",
			expCheckDigit: 8,
		},
		{
			// TD3 sample
			data:          "HA672242<658022549601086<<<<<<<<<<<<<<0",
			expCheckDigit: 8,
		},
	}
	for _, tc := range testCases {
		act := calcCheckdigit(tc.data)
		if act != tc.expCheckDigit {
			t.Errorf("Incorrect check-digit (Exp:%d, Act:%d, Data:%s)", tc.expCheckDigit, act, tc.data)
		}
	}
}

func TestMrzDecode(t *testing.T) {
	testCases := []struct {
		data string
		exp  MRZ
	}{
		{
			// TD1
			data: "I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
			exp:  MRZ{DocumentCode: "I", IssuingState: "UTO", NameOfHolder: MrzName{Primary: "ERIKSSON", Secondary: "ANNA MARIA"}, DocumentNumber: "D23145890", Nationality: "UTO", DateOfBirth: "740812", Sex: "F", DateOfExpiry: "120415", OptionalData: "", OptionalData2: ""},
		},
		{
			// TD2
			data: "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<6",
			exp:  MRZ{DocumentCode: "I", IssuingState: "UTO", NameOfHolder: MrzName{Primary: "ERIKSSON", Secondary: "ANNA MARIA"}, DocumentNumber: "D23145890", Nationality: "UTO", DateOfBirth: "740812", Sex: "F", DateOfExpiry: "120415", OptionalData: ""},
		},
		{
			// TD3
			data: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10",
			exp:  MRZ{DocumentCode: "P", IssuingState: "UTO", NameOfHolder: MrzName{Primary: "ERIKSSON", Secondary: "ANNA MARIA"}, DocumentNumber: "L898902C3", Nationality: "UTO", DateOfBirth: "740812", Sex: "F", DateOfExpiry: "120415", OptionalData: "ZE184226B"},
		},
	}
	for _, tc := range testCases {
		mrz, err := MrzDecode(tc.data)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		if !reflect.DeepEqual(mrz, &(tc.exp)) {
			t.Errorf("Incorrect MRZ\n[Act] %+v\n[Exp] %+v", mrz, tc.exp)
		}
	}
}

func TestMrzDecodeMrziEncode(t *testing.T) {
	testCases := []struct {
		inp_mrz  string
		exp_mrzi string
	}{
		{
			// TD1 (90 chars)
			inp_mrz:  "I<UTOD23145890<7349<<<<<<<<<<<3407127M9507122UTO<<<<<<<<<<<2STEVENSON<<PETER<JOHN<<<<<<<<<",
			exp_mrzi: "D23145890734934071279507122",
		},
		{
			// TD2 (72 chars)
			inp_mrz:  "I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<8",
			exp_mrzi: "D23145890734934071279507122",
		},
		{
			// TD3 (88 chars)
			inp_mrz:  "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10",
			exp_mrzi: "L898902C3674081221204159",
		},
	}
	for _, tc := range testCases {
		mrz, err := MrzDecode(tc.inp_mrz)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		actMrzi := mrz.EncodeMrzi()

		if tc.exp_mrzi != string(actMrzi) {
			t.Errorf("Bad MRZi (Exp:%s) (Act:%s)", tc.exp_mrzi, actMrzi)
		}
	}
}

func TestMrzDecodeTD1BadLen(t *testing.T) {
	// TD1 (90 chars)
	// *** removed last character to make length invalid!
	inp_mrz := "I<UTOD23145890<7349<<<<<<<<<<<3407127M9507122UTO<<<<<<<<<<<2STEVENSON<<PETER<JOHN<<<<<<<<"

	mrz, err := decodeTD1(inp_mrz)

	if err == nil {
		t.Errorf("Error expected")
	}

	if mrz != nil {
		t.Errorf("MRZ not expected for error case")
	}
}

func TestMrzDecodeTD2BadLen(t *testing.T) {
	// TD1 (90 chars)
	// TD2 (72 chars)
	// *** removed last character to make length invalid!
	inp_mrz := "I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<"

	mrz, err := decodeTD2(inp_mrz)

	if err == nil {
		t.Errorf("Error expected")
	}

	if mrz != nil {
		t.Errorf("MRZ not expected for error case")
	}
}

func TestMrzDecodeTD3BadLen(t *testing.T) {
	// TD3 (88 chars)
	// *** removed last character to make length invalid!
	inp_mrz := "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<1"

	mrz, err := decodeTD3(inp_mrz)

	if err == nil {
		t.Errorf("Error expected")
	}

	if mrz != nil {
		t.Errorf("MRZ not expected for error case")
	}
}
