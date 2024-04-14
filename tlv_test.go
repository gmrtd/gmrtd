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

func TestTlvParseAndAccess(t *testing.T) {
	//	70
	//		02: 0x123456
	//		A0
	//			01: 0x7890
	//			02: 0x45
	//			01: 0x67

	var tlvBytes []byte = HexToBytes("70110203123456A00A01027890020145010167")

	var nodes *TlvNodes = TlvDecode(tlvBytes)

	/*
	* basic tests for value access
	 */
	if !bytes.Equal(nodes.GetNode(0x70).GetNode(0x02).GetValue(), HexToBytes("123456")) ||
		!bytes.Equal(nodes.GetNode(0x70).GetNode(0xA0).GetNodeByOccur(0x01, 1).GetValue(), HexToBytes("7890")) ||
		!bytes.Equal(nodes.GetNode(0x70).GetNode(0xA0).GetNodeByOccur(0x02, 1).GetValue(), HexToBytes("45")) ||
		!bytes.Equal(nodes.GetNode(0x70).GetNode(0xA0).GetNodeByOccur(0x01, 2).GetValue(), HexToBytes("67")) {
		t.Errorf("Error fetching value from TLV")
	}

	/*
	* IsValidNode - positive cases
	 */
	if !nodes.IsValidNode() ||
		!nodes.GetNode(0x70).IsValidNode() ||
		!nodes.GetNode(0x70).GetNode(0x02).IsValidNode() ||
		!nodes.GetNode(0x70).GetNode(0xA0).IsValidNode() {
		t.Errorf("IsValidNode error for positive cases")
	}

	/*
	* test that trying to access absent tags does not cause problems
	 */

	if nodes.GetNode(0x71).IsValidNode() ||
		nodes.GetNode(0x70).GetNode(0x02).GetNode(0x01).IsValidNode() ||
		nodes.GetNode(0x70).GetNode(0x02).GetNodeByOccur(0x01, 3).IsValidNode() ||
		nodes.GetNode(0x70).GetNode(0x02).GetNode(0x01).GetNode(0x01).IsValidNode() ||
		nodes.GetNode(0x70).GetNode(0x02).GetNode(0x01).GetNodeByOccur(0x01, 1).IsValidNode() ||
		(nodes.GetNode(0x70).GetNode(0x02).GetNode(0x01).GetNode(0x01).GetTag() != -1) ||
		nodes.GetNodeByOccur(0x70, 2).IsValidNode() ||
		nodes.GetNode(0x70).GetNode(0xA0).GetNodeByOccur(0x02, 2).IsValidNode() {
		t.Errorf("Absent tags not handled correctly")
	}
}
