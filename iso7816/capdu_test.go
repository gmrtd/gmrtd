package iso7816

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
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
		{
			// SELECT Command for MF Selection
			in_cla:    0x00,
			in_ins:    0xA4,
			in_p1:     0x00,
			in_p2:     0x0C,
			in_data:   nil,
			in_le:     0,
			exp_bytes: utils.HexToBytes("00A4000C"),
		},
		{
			// SELECT Command with AID for Application DF Selection
			in_cla:    0x00,
			in_ins:    0xA4,
			in_p1:     0x04,
			in_p2:     0x0C,
			in_data:   utils.HexToBytes("A0000002471001"),
			in_le:     0,
			exp_bytes: utils.HexToBytes("00A4040C07A0000002471001"),
		},
		{
			// READ BINARY - extended length - Le=15575
			in_cla:    0x00,
			in_ins:    0xB0,
			in_p1:     0x00,
			in_p2:     0x04,
			in_data:   utils.HexToBytes(""),
			in_le:     15575,
			exp_bytes: utils.HexToBytes("00b000043cd7"),
		},
		{
			// READ BINARY - extended length - secure message encoded - Le=65536 (ie max)
			// NB 65536 (not 65535) maps to 0x0000
			in_cla:    0x0C,
			in_ins:    0xB0,
			in_p1:     0x00,
			in_p2:     0x04,
			in_data:   utils.HexToBytes("97023cd78e08824f718c83c2e839"),
			in_le:     65536,
			exp_bytes: utils.HexToBytes("0cb0000400000e97023cd78e08824f718c83c2e8390000"),
		},
	}
	for _, tc := range testCases {
		out := NewCApdu(tc.in_cla, tc.in_ins, tc.in_p1, tc.in_p2, tc.in_data, tc.in_le).Encode()

		if !bytes.Equal(tc.exp_bytes, out) {
			t.Errorf("Encode failed (Exp:%x, Act:%x)", tc.exp_bytes, out)
		}
	}
}
