package iso19794

import (
	"bytes"
	_ "embed"
	"testing"
)

//go:embed test_data/ISO19794_Test1_Data.bin
var test1data []byte

//go:embed test_data/ISO19794_Test1_Face.jpg
var test1face []byte

func TestProcessISO19794(t *testing.T) {
	data, err := ProcessISO19794(test1data)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	images := data.GetImages()

	if len(images) != 1 {
		t.Fatalf("1 image expected")
	}

	// verify that the photo matches the reference data
	if !bytes.Equal(images[0], test1face) {
		t.Fatalf("photo differs to expected")
	}
}
