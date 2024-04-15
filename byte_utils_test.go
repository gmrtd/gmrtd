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
	// TODO - convert to table based test

	if !PrintableBytes([]byte("This is a printable string!")) {
		t.Errorf("Should be printable")
	}

	if PrintableBytes([]byte("This is not \a printable string!")) {
		t.Errorf("Should NOT be printable")
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
