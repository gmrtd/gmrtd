package mrz

import "testing"

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
