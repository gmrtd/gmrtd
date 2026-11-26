package iso39794

import (
	"bytes"
	_ "embed" // Import for loading test files
	"encoding/asn1"
	"os"
	"strings"
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

func TestProcessISO39794p5AllFields(t *testing.T) {
	ap, err := ProcessISO39794p5(allFields39794)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	images := ap.Images()

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

func TestProcessISO39794p5MandFields(t *testing.T) {
	ap, err := ProcessISO39794p5(mandFields39794)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	images := ap.Images()

	if len(images) != 1 {
		t.Fatalf("1 image expected")
	}

	// verify that the photo matches the reference data
	if !bytes.Equal(images[0], mandFields39794Face) {
		t.Fatalf("photo differs to expected")
	}
}

//go:embed test_data/ICAO_39794_5_AP_MandFields_InvalidImage.dat
var mandFields39794_invalidImage []byte

func TestProcessISO39794p5MandFieldsInvalidImage(t *testing.T) {
	// TODO
	_, err := ProcessISO39794p5(mandFields39794_invalidImage)
	if err == nil {
		t.Fatalf("Expected error")
	}
}

// withRepresentations re-encodes the ICAO mandatory-fields sample with one representation
// per image, keeping the sample's version block and representation fields otherwise.
func withRepresentations(tb testing.TB, images [][]byte) []byte {
	tb.Helper()
	var face ISO39794_5_AP
	if _, err := asn1.UnmarshalWithParams(mandFields39794, &face, "tag:1"); err != nil {
		tb.Fatal(err)
	}
	reference := face.FaceImageDataBlock.RepresentationBlocks[0]
	face.FaceImageDataBlock.RepresentationBlocks = nil
	for i, data := range images {
		rep := reference
		rep.RepresentationId = i
		rep.ImageRepresentation.Base.ImageRepresentation2DBlock.RepresentationData2D = data
		face.FaceImageDataBlock.RepresentationBlocks = append(face.FaceImageDataBlock.RepresentationBlocks, rep)
	}
	raw, err := asn1.MarshalWithParams(face, "tag:1")
	if err != nil {
		tb.Fatal(err)
	}
	return raw
}

// secondFace is a different real image (the ISO 19794 sample's JPEG face), so tests can
// tell representations apart.
func secondFace(tb testing.TB) []byte {
	tb.Helper()
	jpeg, err := os.ReadFile("../iso19794/test_data/ISO19794_Test1_Face.jpg")
	if err != nil {
		tb.Fatal(err)
	}
	return jpeg
}

func TestProcessISO39794p5Representations(t *testing.T) {
	jp2, jpeg := mandFields39794Face, secondFace(t)
	if bytes.Equal(jp2, jpeg) {
		t.Fatal("fixtures must contain distinct images")
	}
	for _, tc := range []struct {
		name    string
		images  [][]byte
		wantErr string
	}{
		{"none", nil, "missing representation block"},
		{"one", [][]byte{jp2}, ""},
		{"two in file order", [][]byte{jp2, jpeg}, ""},
		{"unrecognised second image", [][]byte{jp2, {0x42}}, "Unknown image type in representation 2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ap, err := ProcessISO39794p5(withRepresentations(t, tc.images))
			if tc.wantErr != "" {
				if ap != nil || err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected no result and %q, got result present=%t, err=%v", tc.wantErr, ap != nil, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			images := ap.Images()
			if len(images) != len(tc.images) {
				t.Fatalf("got %d images, want %d", len(images), len(tc.images))
			}
			for i, want := range tc.images {
				if !bytes.Equal(images[i], want) {
					t.Errorf("image %d differs from representation %d", i, i+1)
				}
			}
		})
	}
}

func TestImagesReturnsCopies(t *testing.T) {
	ap, err := ProcessISO39794p5(withRepresentations(t, [][]byte{mandFields39794Face, secondFace(t)}))
	if err != nil {
		t.Fatal(err)
	}
	images := ap.Images()
	images[0][0] ^= 0xFF
	if again := ap.Images(); !bytes.Equal(again[0], mandFields39794Face) {
		t.Fatal("modifying a returned image changed the parsed representation")
	}
}
