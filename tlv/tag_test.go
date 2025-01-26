package tlv

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestGetTags(t *testing.T) {
	testCases := []struct {
		inp    []byte
		expOut []TlvTag
	}{
		{
			inp:    utils.HexToBytes("5F0E5F115F425F125F13"),
			expOut: []TlvTag{0x5F0E, 0x5F11, 0x5F42, 0x5F12, 0x5F13},
		},
		{
			inp:    utils.HexToBytes("A0305F1F80887F6002"),
			expOut: []TlvTag{0xA0, 0x30, 0x5F1F, 0x80, 0x88, 0x7F60, 0x02},
		},
	}
	for _, tc := range testCases {
		actOut := GetTags(bytes.NewBuffer(tc.inp))

		if !reflect.DeepEqual(actOut, tc.expOut) {
			t.Errorf("TLV Tags differs to expected (Exp:%x, Act:%x)", tc.expOut, actOut)
		}
	}

}

func TestIsConstructed(t *testing.T) {
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
		actIsConstructed := tc.tag.IsConstructed()
		if actIsConstructed != tc.isConstructed {
			t.Errorf("TlvIsConstructedTag error (Tag:%x, Exp:%t, Act:%t)", tc.tag, tc.isConstructed, actIsConstructed)
		}
	}
}
