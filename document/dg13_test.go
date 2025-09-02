package document

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestNewDG13NoData(t *testing.T) {
	if dg13, err := NewDG13(nil); dg13 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if dg13, err := NewDG13([]byte{}); dg13 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewDG13HappyNonTlv(t *testing.T) {
	var dg13bytes []byte = utils.HexToBytes("6D0A01234567890123456789") // valid DG13, with non-TLV content

	var doc Document

	err := doc.NewDG(13, dg13bytes)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if doc.Mf.Lds1.Dg13 == nil {
		t.Errorf("DG13 expected")
	}

	if !bytes.Equal(doc.Mf.Lds1.Dg13.RawData, utils.HexToBytes("6D0A01234567890123456789")) {
		t.Errorf("Bad 'RawData'")
	}

	if !bytes.Equal(doc.Mf.Lds1.Dg13.Content, utils.HexToBytes("01234567890123456789")) {
		t.Errorf("Bad 'Content'")
	}
}

func TestNewDG13Errors(t *testing.T) {
	testCases := []struct {
		data []byte
	}{
		{
			// valid TLV but invalid DG13, as tag 6D is missing
			data: utils.HexToBytes("01021234"),
		},
		{
			// less data than expected
			data: utils.HexToBytes("6D025F"),
		},
		{
			// tag but no length
			data: utils.HexToBytes("6D"),
		},
	}
	for _, tc := range testCases {
		dg13, err := NewDG13(tc.data)

		if err == nil {
			t.Errorf("expected error")
		}

		if dg13 != nil {
			t.Errorf("expected nil DG13")
		}
	}
}
