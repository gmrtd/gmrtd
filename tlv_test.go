package gmrtd

import (
	"bytes"
	"testing"
)

func TestTlv(t *testing.T) {
	data := HexToBytes("31283012060a04007f000702020402040201020201103012060a04007f00070202040604020102020110")

	nodes := TlvDecode(data)

	data2 := nodes.Encode()

	if !bytes.Equal(data, data2) {
		t.Errorf("Decode/Encode mismatch (Exp: %x) (Act: %x)", data, data2)
	}
}

func TestTlvIsConstructedTag(t *testing.T) {
	testCases := []struct {
		tag           TlvTag
		isConstructed bool
	}{
		{
			tag:           0x61,
			isConstructed: true,
		},
		{
			tag:           0x7f61,
			isConstructed: true,
		},
		{
			tag:           0x5f1f,
			isConstructed: false,
		},
		{
			tag:           0x81,
			isConstructed: false,
		},
	}
	for _, tc := range testCases {
		actIsConstructed := TlvIsConstructedTag(tc.tag)
		if actIsConstructed != tc.isConstructed {
			t.Errorf("TlvIsConstructedTag error (Tag:%x, Exp:%t, Act:%t)", tc.tag, tc.isConstructed, actIsConstructed)
		}
	}

}

func TestTlvDecode(t *testing.T) {

	inp := HexToBytes("61085f1f050123456789")
	out := TlvDecode(inp)

	act := out.GetNode(0x61).GetNode(0x5f1f).GetValue()

	exp := HexToBytes("0123456789")

	if !bytes.Equal(exp, act) {
		t.Errorf("TLV Decode error (Exp:%x, Act:%x)", exp, act)
	}
}

func TestTlvLength(t *testing.T) {
	testCases := []struct {
		inp    uint32
		expOut []byte
	}{
		{
			inp:    0x7F,
			expOut: HexToBytes("7F"),
		},
		{
			inp:    0x80,
			expOut: HexToBytes("8180"),
		},
		{
			inp:    0xFF,
			expOut: HexToBytes("81FF"),
		},
		{
			inp:    0xFFFF,
			expOut: HexToBytes("82FFFF"),
		},
		{
			inp:    0xFFFFFF,
			expOut: HexToBytes("83FFFFFF"),
		},
		{
			inp:    0xFFFFFFFF,
			expOut: HexToBytes("84FFFFFFFF"),
		},
	}
	for _, tc := range testCases {
		actOut := TlvEncodeLength(int(tc.inp))

		if !bytes.Equal(actOut, tc.expOut) {
			t.Errorf("Invalid TLV Length encoding (Len:%x, ExpBytes:%x, ActBytes:%x)", tc.inp, tc.expOut, actOut)
		}

		// test decode
		{
			var bBuf *bytes.Buffer = bytes.NewBuffer(actOut)
			decodedLen := TlvGetLength(bBuf)

			if decodedLen != int(tc.inp) {
				t.Errorf("TLV Length decode error (EncLen:%x, ExpLen:%x, ActLen:%x)", actOut, tc.inp, decodedLen)
			}

			if len(bBuf.Bytes()) > 0 {
				t.Errorf("Unexpected data left in buffer")
			}
		}
	}
}
