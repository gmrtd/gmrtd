package iso39794

import (
	"bytes"
	_ "embed"
	"testing"
)

func TestProcessISO39794_5_AP_BadData(t *testing.T) {
	var badData []byte = []byte{0xA1, 0x12, 0x12, 0x34}

	_, err := ProcessISO39794_5_AP(badData)
	if err == nil {
		t.Fatalf("Error Expected")
	}
}

func TestProcessISO39794_5_AP_NilData(t *testing.T) {
	_, err := ProcessISO39794_5_AP(nil)
	if err == nil {
		t.Fatalf("Error Expected")
	}
}

//go:embed test_data/ICAO_39794_5_AP_AllFields.dat
var allFields39794 []byte

//go:embed test_data/ICAO_39794_5_AP_Face.jpg
var allFields39794Face []byte

func TestNewDG2AllFields39794(t *testing.T) {
	ap, err := ProcessISO39794_5_AP(allFields39794)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	images := ap.GetImages()

	if len(images) != 1 {
		t.Fatalf("1 image expected")
	}

	// verify that the photo matches the reference data
	if !bytes.Equal(images[0], allFields39794Face) {
		t.Fatalf("photo differs to expected")
	}
}

//go:embed test_data/ICAO_39794_5_AP_MandFields.dat
var mandFields39794 []byte

//go:embed test_data/ICAO_39794_5_AP_Face.jpg
var mandFields39794Face []byte

func TestNewDG2MandFields39794(t *testing.T) {
	ap, err := ProcessISO39794_5_AP(mandFields39794)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	images := ap.GetImages()

	if len(images) != 1 {
		t.Fatalf("1 image expected")
	}

	// verify that the photo matches the reference data
	if !bytes.Equal(images[0], mandFields39794Face) {
		t.Fatalf("photo differs to expected")
	}
}
