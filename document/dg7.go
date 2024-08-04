package document

import (
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

const DG7Tag = 0x67

type DG7 struct {
	RawData []byte
	Images  []DG7Image
}

type DG7Image struct {
	Image []byte
}

// 67
//		02		M(1)	Number of displayed signature or usual marks (1-9)
//		5F43	M(1-9)	Displayed signature or usual mark representation

// Note.— Data Element 02 (tag 5F43) SHALL be encoded as defined in [ISO/IEC 10918], using the JFIF option, or
//		  [ISO/IEC 15444] using JPEG 2000 image coding system.

func NewDG7(data []byte) (*DG7, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *DG7 = new(DG7)

	out.RawData = slices.Clone(data)

	out.RawData = slices.Clone(data)

	nodes := tlv.TlvDecode(out.RawData)

	rootNode := nodes.GetNode(DG7Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG7Tag)
	}

	{
		var numImages int
		{
			tmp := rootNode.GetNode(0x02).GetValue()
			if len(tmp) != 1 {
				return nil, fmt.Errorf("DG7 tag 02 length must be 1 byte (actLen:%1d)", len(tmp))
			}

			numImages = int(tmp[0])

			if (numImages < 1) || (numImages > 9) {
				return nil, fmt.Errorf("DG7 tag 02 must be 1-9 [act:%1d]", numImages)
			}
		}

		for occurrence := 1; occurrence <= numImages; occurrence++ {
			imageBytes := rootNode.GetNodeByOccur(0x5F43, occurrence).GetValue()

			if !utils.IsImage(imageBytes) {
				return nil, fmt.Errorf("unknown image type [prefixBytes:%x]", imageBytes[0:10])
			}

			out.Images = append(out.Images, DG7Image{Image: slices.Clone(imageBytes)})
		}

	}

	return out, nil
}
