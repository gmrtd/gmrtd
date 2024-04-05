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
