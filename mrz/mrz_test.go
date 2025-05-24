package mrz

import (
	"reflect"
	"testing"
)

func TestParseName(t *testing.T) {
	testCases := []struct {
		input   string
		expName MrzName
	}{
		{
			input:   "Primary  Secondary",
			expName: MrzName{Primary: "Primary", Secondary: "Secondary"},
		},
		{
			input:   "Primary name only",
			expName: MrzName{Primary: "Primary name only", Secondary: ""},
		},
	}
	for _, tc := range testCases {
		actName, err := ParseName(tc.input)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		if actName.Primary != tc.expName.Primary {
			t.Errorf("Primary name differs to expected (exp:%s) (act:%s)", tc.expName.Primary, actName.Primary)
		}

		if actName.Secondary != tc.expName.Secondary {
			t.Errorf("Secondary name differs to expected (exp:%s) (act:%s)", tc.expName.Secondary, actName.Secondary)
		}
	}
}

func TestParseNameTooManyComponentsErr(t *testing.T) {
	_, err := ParseName("Invalid name  with  three components")

	if err == nil {
		t.Errorf("error expected")
	}
}

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
		expCheckDigit string
	}{
		{
			// TD1
			data:          "D231458907<<<<<<<<<<<<<<<34071279507122<<<<<<<<<<<",
			expCheckDigit: "2",
		},
		{
			// TD2 sample
			data:          "HA672242<658022549601086<<<<<<<",
			expCheckDigit: "8",
		},
		{
			// TD3 sample
			data:          "HA672242<658022549601086<<<<<<<<<<<<<<0",
			expCheckDigit: "8",
		},
	}
	for _, tc := range testCases {
		act, err := calcCheckdigit(tc.data)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		if act != tc.expCheckDigit {
			t.Errorf("Incorrect check-digit (Exp:%s, Act:%s, Data:%s)", tc.expCheckDigit, act, tc.data)
		}
	}
}

func TestCalcCheckdigitBadCharErr(t *testing.T) {
	var badData string = "HA672242<658022549601086?<<<<<<"

	_, err := calcCheckdigit(badData)

	if err == nil {
		t.Errorf("expected error")
	}
}

func TestVerifyCheckdigitEmptyWithoutCheckDigitOk(t *testing.T) {
	// special handling for case where the string is empty and the check-digit is not set
	verifyCheckdigit("<<<<<<<<", "<")
}

func TestVerifyCheckdigitAtoiErr(t *testing.T) {
	// NB trigger Atoi error by passing non-integer value for the check-digit
	err := verifyCheckdigit("123456789", "A")

	if err == nil {
		t.Errorf("expected error, but didn't get")
	}
}

func TestVerifyCheckdigitErr(t *testing.T) {
	// NB valid check-digit would be '7', so give '1' to trigger validation error
	err := verifyCheckdigit("123456789", "1")

	if err == nil {
		t.Errorf("expected error, but didn't get")
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
			exp:  MRZ{DocumentCode: "I", IssuingState: "UTO", NameOfHolder: &MrzName{Primary: "ERIKSSON", Secondary: "ANNA MARIA"}, DocumentNumber: "D23145890", Nationality: "UTO", DateOfBirth: "740812", Sex: "F", DateOfExpiry: "120415", OptionalData: "", OptionalData2: ""},
		},
		{
			// TD2
			data: "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<6",
			exp:  MRZ{DocumentCode: "I", IssuingState: "UTO", NameOfHolder: &MrzName{Primary: "ERIKSSON", Secondary: "ANNA MARIA"}, DocumentNumber: "D23145890", Nationality: "UTO", DateOfBirth: "740812", Sex: "F", DateOfExpiry: "120415", OptionalData: ""},
		},
		{
			// TD3
			data: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10",
			exp:  MRZ{DocumentCode: "P", IssuingState: "UTO", NameOfHolder: &MrzName{Primary: "ERIKSSON", Secondary: "ANNA MARIA"}, DocumentNumber: "L898902C3", Nationality: "UTO", DateOfBirth: "740812", Sex: "F", DateOfExpiry: "120415", OptionalData: "ZE184226B"},
		},
		{
			// test TD3 that is used by other UTs (e.g. Passive-Auth)
			data: "P<D<<DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<D123456785UTO6508092M3505207<<<<<<<<<<<<<<<0",
			exp:  MRZ{DocumentCode: "P", IssuingState: "D", NameOfHolder: &MrzName{Primary: "DOE", Secondary: "JOHN"}, DocumentNumber: "D12345678", Nationality: "UTO", DateOfBirth: "650809", Sex: "M", DateOfExpiry: "350520"},
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

		actMrzi, err := mrz.EncodeMrzi()
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		if tc.exp_mrzi != string(actMrzi) {
			t.Errorf("Bad MRZi (Exp:%s) (Act:%s)", tc.exp_mrzi, actMrzi)
		}
	}
}

func TestMrzDecodeErrors(t *testing.T) {
	testCases := []struct {
		data string
	}{
		{
			// TD1
			// invalid document-number check-digit (7->5)
			data: "I<UTOD231458905<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
		},
		{
			// TD1
			// invalid date-of-birth check-digit (2->4)
			data: "I<UTOD231458907<<<<<<<<<<<<<<<7408124F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
		},
		{
			// TD1
			// invalid date-of-expiry check-digit (9->1)
			data: "I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204151UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
		},
		{
			// TD1
			// invalid composite check-digit (6->7)
			data: "I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<7ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
		},
		{
			// TD1 (90 chars)
			// *** removed last character to make length invalid!
			data: "I<UTOD23145890<7349<<<<<<<<<<<3407127M9507122UTO<<<<<<<<<<<2STEVENSON<<PETER<JOHN<<<<<<<<",
		},
		{
			// TD2
			// invalid document-number check-digit (7->6)
			data: "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458906UTO7408122F1204159<<<<<<<6",
		},
		{
			// TD2
			// invalid date-of-birth check-digit (2->3)
			data: "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408123F1204159<<<<<<<6",
		},
		{
			// TD2
			// invalid date-of-expiry check-digit (9->8)
			data: "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204158<<<<<<<6",
		},
		{
			// TD2
			// invalid composite check-digit (6->8)
			data: "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<8",
		},

		{
			// TD2 (72 chars)
			// *** removed last character to make length invalid!
			data: "I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<",
		},
		{
			// TD3
			// invalid document-number check-digit (6->4)
			data: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C34UTO7408122F1204159ZE184226B<<<<<10",
		},
		{
			// TD3
			// invalid date-of-birth check-digit (2->6)
			data: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408126F1204159ZE184226B<<<<<10",
		},
		{
			// TD3
			// invalid date-of-expiry check-digit (9->1)
			data: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204151ZE184226B<<<<<10",
		},
		{
			// TD3
			// invalid optional-data check-digit (1->2)
			data: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<20",
		},
		{
			// TD3
			// invalid composite check-digit (0->2)
			data: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<12",
		},
		{
			// TD3 (88 chars)
			// *** removed last character to make length invalid!
			data: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<1",
		},
	}
	for _, tc := range testCases {
		mrz, err := MrzDecode(tc.data)

		if err == nil {
			t.Errorf("Error expected")
		}

		if mrz != nil {
			t.Errorf("MRZ not expected for error case")
		}
	}
}
