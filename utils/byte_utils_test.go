package utils

import (
	"bytes"
	"strings"
	"testing"
)

func TestXorBytes(t *testing.T) {
	in1 := []byte{0x00, 0x00, 0xFF, 0xFF}
	in2 := []byte{0x00, 0xFF, 0x00, 0xFF}
	exp := []byte{0x00, 0xFF, 0xFF, 0x00}

	out := XorBytes(in1, in2)

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
		data []byte
		exp  bool
	}{
		{
			data: []byte("This is a printable string!"),
			exp:  true,
		},
		{
			data: []byte("This is not \a printable string!"),
			exp:  false,
		},
		{
			data: []byte("This is not \a printable string! \xff"),
			exp:  false,
		},
	}
	for _, tc := range testCases {
		act := PrintableBytes(tc.data)

		if act != tc.exp {
			t.Errorf("PrintableBytes error (Exp:%t, Act:%t)", tc.exp, act)
		}
	}
}

func TestIsImage(t *testing.T) {
	// invalid image data - i.e. doesn't have a recognised image header
	var imageBytes []byte = HexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")

	if IsImage(imageBytes) {
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
		act := BytesToInt(tc.bytes)

		if act != tc.exp {
			t.Errorf("bytesToInt error (Bytes:%x, Exp:%d, Act:%d)", tc.bytes, tc.exp, act)
		}
	}
}

func TestUInt16ToBytes(t *testing.T) {
	testCases := []struct {
		value    int
		expBytes []byte
	}{
		{
			value:    0x1234,
			expBytes: []byte{0x12, 0x34},
		},
	}
	for _, tc := range testCases {
		actBytes := UInt16ToBytes(uint16(tc.value))

		if !bytes.Equal(actBytes, tc.expBytes) {
			t.Errorf("Unexpected output (Exp:%x) (Act:%x)", tc.expBytes, actBytes)
		}
	}
}

func TestUInt32ToBytes(t *testing.T) {
	testCases := []struct {
		value    int
		expBytes []byte
	}{
		{
			value:    0x12345678,
			expBytes: []byte{0x12, 0x34, 0x56, 0x78},
		},
	}
	for _, tc := range testCases {
		actBytes := UInt32ToBytes(uint32(tc.value))

		if !bytes.Equal(actBytes, tc.expBytes) {
			t.Errorf("Unexpected output (Exp:%x) (Act:%x)", tc.expBytes, actBytes)
		}
	}
}

func TestUInt64ToBytes(t *testing.T) {
	testCases := []struct {
		value    int
		expBytes []byte
	}{
		{
			value:    0x1234567890abcdef,
			expBytes: []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef},
		},
	}
	for _, tc := range testCases {
		actBytes := UInt64ToBytes(uint64(tc.value))

		if !bytes.Equal(actBytes, tc.expBytes) {
			t.Errorf("Unexpected output (Exp:%x) (Act:%x)", tc.expBytes, actBytes)
		}
	}
}
