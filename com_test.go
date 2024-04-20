package gmrtd

import (
	"bytes"
	"testing"
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
	data := HexToBytes("60145F0104303130365F36063034303030305C026175")

	com, err := NewCOM(data)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if com.LdsVersion != "0106" {
		t.Errorf("Incorrect LdsVersion")
	}

	if com.UnicodeVersion != "040000" {
		t.Errorf("Incorrect UnicodeVersion")
	}

	if !bytes.Equal(com.TagList, HexToBytes("6175")) {
		t.Errorf("Incorrect TagList")
	}
}

func TestNewCOMError(t *testing.T) {
	{
		data := HexToBytes("55021234")

		if _, err := NewCOM(data); err == nil {
			t.Errorf("Error expected for missing tag 60")
		}
	}

	{
		data := HexToBytes("60155F010530313036305F36063034303030305C026175")

		if _, err := NewCOM(data); err == nil {
			t.Errorf("Error expected for tag 5f01 not being 4 bytes")
		}
	}

	{
		data := HexToBytes("60135F0104303130365F360534303030305C026175")

		if _, err := NewCOM(data); err == nil {
			t.Errorf("Error expected for tag 5f36 not being 6 bytes")
		}
	}
}
