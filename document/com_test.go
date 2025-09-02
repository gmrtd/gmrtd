package document

import (
	"slices"
	"testing"

	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

func TestNewCOMNoData(t *testing.T) {
	if com, err := NewCOM(nil); (com != nil) || (err != nil) {
		t.Errorf("Should be nil when no input data provided")
	}
	if com, err := NewCOM([]byte{}); (com != nil) || (err != nil) {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewCOM(t *testing.T) {
	// EF.COM test data from 9303-p10
	data := utils.HexToBytes("60145F0104303130365F36063034303030305C026175")

	var expLdsVersion string = "0106"
	var expUnicodeVersion = "040000"
	var expTagList []tlv.TlvTag = []tlv.TlvTag{0x61, 0x75}

	com, err := NewCOM(data)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if com.LdsVersion != expLdsVersion {
		t.Errorf("Incorrect LdsVersion (Exp:%s, Act:%s)", expLdsVersion, com.LdsVersion)
	}

	if com.UnicodeVersion != expUnicodeVersion {
		t.Errorf("Incorrect UnicodeVersion (Exp:%s, Act:%s)", expUnicodeVersion, com.UnicodeVersion)
	}

	if !slices.Equal(com.TagList, expTagList) {
		t.Errorf("TagList differs to expected")
	}
}

func TestNewCOMErrors(t *testing.T) {
	testCases := []struct {
		data []byte
	}{
		{
			// Error expected for missing tag 60
			data: utils.HexToBytes("55021234"),
		},
		{
			// Error expected for tag 5f01 not being 4 bytes
			data: utils.HexToBytes("60155F010530313036305F36063034303030305C026175"),
		},
		{
			// Error expected for tag 5f36 not being 6 bytes
			data: utils.HexToBytes("60135F0104303130365F360534303030305C026175"),
		},
		{
			// Error expected due to invalid tags in 5C
			data: utils.HexToBytes("60195F0104303130375F36063034303030305C076175636B6C6D5F"),
			//                                                                          || was 6E, changed to contain incomplete tag (5F)
		},
		{
			// invalid TLV encoding - insufficient bytes
			data: utils.HexToBytes("02101234"),
		},
	}
	for _, tc := range testCases {
		com, err := NewCOM(tc.data)

		if err == nil {
			t.Errorf("expected error")
		}

		if com != nil {
			t.Errorf("expected nil COM")
		}
	}
}
