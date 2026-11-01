package mrz

import (
	"strings"
	"testing"
)

func FuzzMrzDecode(f *testing.F) {
	f.Add("")
	// TD1
	f.Add("I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<")
	// TD2
	f.Add("I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<6")
	// TD3
	f.Add("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10")
	f.Add("P<D<<DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<D123456785UTO6508092M3505207<<<<<<<<<<<<<<<0")

	f.Fuzz(func(t *testing.T, data string) {
		// MrzDecode is expected to return an error for malformed input, never panic
		_, _ = MrzDecode(data)
	})
}

// FuzzConvertMrzToMrzi covers the path a scanned MRZ takes into the BAC/PACE password
// (password.NewPasswordMrz), which extracts the MRZ information directly rather than via
// MrzDecode. A space left in the MRZi gives a key the chip won't match (see
// TestConvertMrzToMrzi), and the MRZi is the fixed-width document number, date of birth and date
// of expiry, each with its check digit (TD1/TD2 document numbers may extend into optional data).
func FuzzConvertMrzToMrzi(f *testing.F) {
	f.Add("")
	// TD1, standard and extended document-number
	f.Add("I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<")
	f.Add("I<UTOD23145890<7349<<<<<<<<<<<3407127M9507122UTO<<<<<<<<<<<2STEVENSON<<PETER<JOHN<<<<<<<<<")
	// TD2, standard and extended document-number
	f.Add("I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<6")
	f.Add("I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<8")
	// TD3
	f.Add("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10")

	f.Fuzz(func(t *testing.T, data string) {
		mrzi, err := ConvertMrzToMrzi(data)
		if err != nil {
			return
		}
		if strings.Contains(mrzi, " ") {
			t.Fatalf("MRZi %q contains a space", mrzi)
		}
		if len(mrzi) < 24 || (len(data) == MRZLengthTD3 && len(mrzi) != 24) {
			t.Fatalf("MRZi %q has unexpected length %d", mrzi, len(mrzi))
		}
	})
}
