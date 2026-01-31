package tlv

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestGetLength(t *testing.T) {
	testCases := []struct {
		inp    int
		expOut []byte
	}{
		{
			// special case for indefinite-length mode
			inp:    -1,
			expOut: utils.HexToBytes("80"),
		},
		{
			inp:    0x7F,
			expOut: utils.HexToBytes("7F"),
		},
		{
			inp:    0x80,
			expOut: utils.HexToBytes("8180"),
		},
		{
			inp:    0xFF,
			expOut: utils.HexToBytes("81FF"),
		},
		{
			inp:    0xFFFF,
			expOut: utils.HexToBytes("82FFFF"),
		},
		{
			inp:    0xFFFFFF,
			expOut: utils.HexToBytes("83FFFFFF"),
		},
		{
			inp:    0xFFFFFFFF,
			expOut: utils.HexToBytes("84FFFFFFFF"),
		},
	}
	for _, tc := range testCases {
		actOut := TlvLength(tc.inp).Encode()

		if !bytes.Equal(actOut, tc.expOut) {
			t.Errorf("Invalid TLV Length encoding (Len:%x, ExpBytes:%x, ActBytes:%x)", tc.inp, tc.expOut, actOut)
		}

		// test decode
		{
			var bBuf *bytes.Buffer = bytes.NewBuffer(actOut)
			decodedLen, err := ParseLength(bBuf)

			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			if decodedLen != TlvLength(tc.inp) {
				t.Errorf("TLV Length decode error (EncLen:%x, ExpLen:%x, ActLen:%x)", actOut, tc.inp, decodedLen)
			}

			if len(bBuf.Bytes()) > 0 {
				t.Errorf("Unexpected data left in buffer")
			}
		}
	}
}

func TestGetLengthBadLengthErr(t *testing.T) {
	var buf *bytes.Buffer = bytes.NewBuffer(utils.HexToBytes("85000000000199"))

	_, err := ParseLength(buf)

	if err == nil {
		t.Errorf("error expected")
	}
}

func TestEncodeLengthBadLengthErr(t *testing.T) {
	defer func() { _ = recover() }()

	// trigger error by using length > 32-bits
	_ = TlvLength(0x1ffffffff).Encode()

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestEncodeLengthBadLengthErr2(t *testing.T) {
	defer func() { _ = recover() }()

	// trigger error by using length > 32-bits
	_ = TlvLength(-2147483648).Encode()

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}
