package gmrtd

import (
	"bytes"
	"testing"
)

func TestEncode(t *testing.T) {
	testCases := []struct {
		in_cla    byte
		in_ins    byte
		in_p1     byte
		in_p2     byte
		in_data   []byte
		in_le     int
		exp_bytes []byte
	}{
		// SELECT Command for MF Selection
		{
			in_cla:    0x00,
			in_ins:    0xA4,
			in_p1:     0x00,
			in_p2:     0x0C,
			in_data:   nil,
			in_le:     0,
			exp_bytes: HexToBytes("00A4000C"),
		},
		// SELECT Command with AID for Application DF Selection
		{
			in_cla:    0x00,
			in_ins:    0xA4,
			in_p1:     0x04,
			in_p2:     0x0C,
			in_data:   HexToBytes("A0000002471001"),
			in_le:     0,
			exp_bytes: HexToBytes("00A4040C07A0000002471001"),
		},
	}
	for _, tc := range testCases {
		out := NewCApdu(tc.in_cla, tc.in_ins, tc.in_p1, tc.in_p2, tc.in_data, tc.in_le).Encode()

		if !bytes.Equal(tc.exp_bytes, out) {
			t.Errorf("Encode failed (Exp:%x, Act:%x)", tc.exp_bytes, out)
		}
	}
}
