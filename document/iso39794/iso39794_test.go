package iso39794

import (
	"bytes"
	_ "embed"
	"testing"
)

func TestProcessISO39794p5badData(t *testing.T) {
	var badData []byte = []byte{0xA1, 0x12, 0x12, 0x34}

	_, err := ProcessISO39794p5(badData)
	if err == nil {
		t.Fatalf("Error Expected")
	}
}

func TestProcessISO39794p5nilData(t *testing.T) {
	_, err := ProcessISO39794p5(nil)
	if err == nil {
		t.Fatalf("Error Expected")
	}
}

//go:embed test_data/ICAO_39794_5_AP_AllFields.dat
var allFields39794 []byte

//go:embed test_data/ICAO_39794_5_AP_Face.jpg
var allFields39794Face []byte

func TestNewDG2AllFields39794(t *testing.T) {
	ap, err := ProcessISO39794p5(allFields39794)
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
	ap, err := ProcessISO39794p5(mandFields39794)
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
