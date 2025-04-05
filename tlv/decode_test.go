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

	act := out.GetNode(0x61).GetNode(0x5f1f).GetValue()

	exp := utils.HexToBytes("0123456789")

	if !bytes.Equal(exp, act) {
		t.Errorf("TLV Decode error (Exp:%x, Act:%x)", exp, act)
	}
}
