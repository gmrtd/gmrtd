package tlv

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestDecode(t *testing.T) {
	inp := utils.HexToBytes("61085f1f050123456789")
	out, err := Decode(inp)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	act := out.NodeByTag(0x61).NodeByTag(0x5f1f).Value()

	exp := utils.HexToBytes("0123456789")

	if !bytes.Equal(exp, act) {
		t.Errorf("TLV Decode error (Exp:%x, Act:%x)", exp, act)
	}
}

func TestDecodeIndefinteLength(t *testing.T) {
	inp := utils.HexToBytes("61805f1f0501234567890000")
	out, err := Decode(inp)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	act := out.NodeByTag(0x61).NodeByTag(0x5f1f).Value()

	exp := utils.HexToBytes("0123456789")

	if !bytes.Equal(exp, act) {
		t.Errorf("TLV Decode error (Exp:%x, Act:%x)", exp, act)
	}
}

func TestDecodeErrors(t *testing.T) {
	testCases := []struct {
		data []byte
	}{
		{
			// less data than expected
			data: utils.HexToBytes("61095f1f050123456789"),
			//						  || should be 08
		},
		{
			// less data than expected.. normal node not composite
			data: utils.HexToBytes("61085f1f060123456789"),
			//						  		|| should be 05
		},
		{
			// tag but no length/data
			data: utils.HexToBytes("61"),
			//						|| tag only, missing length/data
		},
		{
			// indefinite length with normal tag (but only allowed for composites)
			data: utils.HexToBytes("61085f1f8001234567890000"),
			//						  		|| indefinite-length not allowed unless composite tag
		},
		{
			// indefinite length, but contains a normal node with less data than expected
			data: utils.HexToBytes("61805f1f110000"),
			//                              || less data than expected (x11, but really x00)
		},
	}
	for _, tc := range testCases {
		_, err := Decode(tc.data)
		if err == nil {
			t.Errorf("Expected error")
		}
	}
}

func TestMustDecodeErrors(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	// less data than expected
	_ = MustDecode(utils.HexToBytes("61095f1f050123456789"))
	//						           || should be 08

	t.Errorf("should have panicked")
}
