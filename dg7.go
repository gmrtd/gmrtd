package gmrtd

import (
	"log"
	"slices"
)

type DG7 struct {
	RawData []byte
	Images  []DG7Image
}

type DG7Image struct {
	Image []byte
}

func NewDG7(data []byte) *DG7 {
	if len(data) < 1 {
		return nil
	}

	var out *DG7 = new(DG7)

	out.RawData = slices.Clone(data)

	tlv := TlvDecode(data)

	// 67
	//		02		M(1)	Number of displayed signature or usual marks (1-9)
	//		5F43	M(1-9)	Displayed signature or usual mark representation

	// Note.— Data Element 02 (tag 5F43) SHALL be encoded as defined in [ISO/IEC 10918], using the JFIF option, or
	//		  [ISO/IEC 15444] using JPEG 2000 image coding system.

	tag67 := tlv.GetNode(0x67)
	if !tag67.IsValidNode() {
		log.Panicf("DG7 tag 67 missing")
	}

	var numImages int
	{
		tmp := tag67.GetNode(0x02).GetValue()
		if len(tmp) != 1 {
			log.Panicf("DG7 tag 02 length must be 1 byte (actLen:%1d)", len(tmp))
		}

		numImages = int(tmp[0])

		if (numImages < 1) || (numImages > 9) {
			log.Panicf("DG7 tag 02 must be 1-9 [act:%1d]", numImages)
		}
	}

	for occurrence := 1; occurrence <= numImages; occurrence++ {
		imageBytes := tag67.GetNodeByOccur(0x5F43, occurrence).GetValue()

		if !isImage(imageBytes) {
			log.Panicf("Unknown image type [prefixBytes:%X]", imageBytes[0:10])
		}

		out.Images = append(out.Images, DG7Image{Image: slices.Clone(imageBytes)})
	}

	return out
}
