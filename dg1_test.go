package gmrtd

import (
	"testing"
)

func TestNewDG1NoData(t *testing.T) {
	if NewDG1(nil) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
	if NewDG1([]byte{}) != nil {
		t.Errorf("Should be nil when no input data provided")
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
			dg1:  HexToBytes("614B5F1F48493C55544F4552494B53534F4E3C3C414E4E413C4D415249413C3C3C3C3C3C3C3C3C3C3C4432333134353839303755544F3734303831323246313230343135393C3C3C3C3C3C3C36"),
			mrzi: "D23145890774081221204159",
		},
		{
			// TD3 sample with missing 'optional data' and unset checkdigit (as seen on AT passport)
			// P<SURNAME<<FIRSTNAME<<<<<<<<<<<<<<<<<<<<<<<<DOCNUM<<<8UTO8201054M3401011<<<<<<<<<<<<<<<6
			dg1:  HexToBytes("615b5f1f58503C5355524E414D453C3C46495253544E414D453C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C444F434E554D3C3C3C3855544F383230313035344D333430313031313C3C3C3C3C3C3C3C3C3C3C3C3C3C3C36"),
			mrzi: "DOCNUM<<<882010543401011",
		},
	}
	for _, tc := range testCases {
		// parse DG1 data
		dg1 := NewDG1(tc.dg1)

		// generate MRZi (as a quick way of verifying)
		actMrzi := dg1.Mrz.EncodeMrzi()

		if actMrzi != tc.mrzi {
			t.Errorf("DG1 MRZi mismatch (Exp:%s, Act:%s)", tc.mrzi, actMrzi)
		}
	}
}
