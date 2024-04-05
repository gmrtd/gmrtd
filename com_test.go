package gmrtd

import (
	"bytes"
	"testing"
)

func TestNewCOM(t *testing.T) {
	// EF.COM test data from 9303-p10
	data := HexToBytes("60145F0104303130365F36063034303030305C026175")

	com := NewCOM(data)

	if !bytes.Equal(com.LdsVersion, HexToBytes("30313036")) {
		t.Errorf("Incorrect LdsVersion")
	}

	if !bytes.Equal(com.UnicodeVersion, HexToBytes("303430303030")) {
		t.Errorf("Incorrect UnicodeVersion")
	}

	if !bytes.Equal(com.TagList, HexToBytes("6175")) {
		t.Errorf("Incorrect TagList")
	}
}
