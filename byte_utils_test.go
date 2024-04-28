package gmrtd

import (
	"bytes"
	"strings"
	"testing"
)

func TestXorBytes(t *testing.T) {
	in1 := []byte{0x00, 0x00, 0xFF, 0xFF}
	in2 := []byte{0x00, 0xFF, 0x00, 0xFF}
	exp := []byte{0x00, 0xFF, 0xFF, 0x00}

	out := xorBytes(in1, in2)

	if !bytes.Equal(exp, out) {
		t.Errorf("XOR mismatch")
	}
}

func TestBytesToHex(t *testing.T) {
	inp := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	exp := "0123456789ABCDEF"

	act := BytesToHex(inp)

	if !strings.EqualFold(act, exp) {
		t.Errorf("BytesToHex conversion error (exp:%s, act:%s)", exp, act)
	}
}

func TestPrintableBytes(t *testing.T) {
	testCases := []struct {
		str string
		exp bool
	}{
		{
			str: "This is a printable string!",
			exp: true,
		},
		{
			str: "This is not \a printable string!",
			exp: false,
		},
	}
	for _, tc := range testCases {
		act := PrintableBytes([]byte(tc.str))

		if act != tc.exp {
			t.Errorf("PrintableBytes error (Exp:%t, Act:%t)", tc.exp, act)
		}
	}
}

func TestIsImage(t *testing.T) {
	// invalid image data - i.e. doesn't have a recognised image header
	var imageBytes []byte = HexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")

	if isImage(imageBytes) {
		t.Errorf("Should NOT be an image")
	}

	// TODO - should have positive tests also
}

func TestBytesToInt(t *testing.T) {
	testCases := []struct {
		bytes []byte
		exp   int
	}{
		{
			bytes: nil,
			exp:   0,
		},
		{
			bytes: []byte{},
			exp:   0,
		},
		{
			bytes: []byte{0xff},
			exp:   255,
		},
		{
			bytes: []byte{0xff, 0xff},
			exp:   65535,
		},
		{
			bytes: []byte{0x1, 0x0, 0x1},
			exp:   65537,
		},
	}
	for _, tc := range testCases {
		act := bytesToInt(tc.bytes)

		if act != tc.exp {
			t.Errorf("bytesToInt error (Bytes:%x, Exp:%d, Act:%d)", tc.bytes, tc.exp, act)
		}
	}
}
