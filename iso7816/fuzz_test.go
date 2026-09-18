package iso7816

import (
	"bytes"
	"testing"
)

func FuzzParseRApdu(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x90, 0x00})
	f.Add([]byte{0x01, 0x02, 0x03, 0x90, 0x00})
	f.Add([]byte{0x6A, 0x82})

	f.Fuzz(func(t *testing.T, data []byte) {
		rapdu, err := ParseRApdu(data)
		if err != nil {
			return
		}
		if rapdu == nil {
			t.Fatalf("ParseRApdu returned nil rapdu with nil error")
		}

		// roundtrip invariant: Encode() must reproduce the original bytes exactly
		if !bytes.Equal(rapdu.Encode(), data) {
			t.Fatalf("Encode() did not reproduce original bytes (data:%x, encoded:%x)", data, rapdu.Encode())
		}
	})
}
