package document

import (
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

// DG7Tag is the tag of the DG7 root data object.
const DG7Tag = 0x67

// DG7 is data group 7, the displayed signature or usual mark images.
type DG7 struct {
	RawData []byte     `json:"rawData,omitempty"`
	Images  []DG7Image `json:"images,omitempty"`
}

// DG7Image is a displayed signature or usual mark image from DG7.
type DG7Image struct {
	Image []byte `json:"image,omitempty"`
}

// 67
//		02		M(1)	Number of displayed signature or usual marks (1-9)
//		5F43	M(1-9)	Displayed signature or usual mark representation

// Note.— Data Element 02 (tag 5F43) SHALL be encoded as defined in [ISO/IEC 10918], using the JFIF option, or
//		  [ISO/IEC 15444] using JPEG 2000 image coding system.

// GetRawData returns the raw DG7 bytes as read from the chip.
func (f *DG7) GetRawData() []byte { return f.RawData }

// NewDG7 parses DG7. It returns nil and no error if data is empty, and an error if the
// TLV is malformed, the root tag is missing, the image count (tag 02) is not a single
// byte of 1-9, or an image is missing or not in a recognised image format.
func NewDG7(data []byte) (*DG7, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *DG7 = new(DG7)

	out.RawData = slices.Clone(data)

	out.RawData = slices.Clone(data)

	nodes, err := tlv.Decode(out.RawData)
	if err != nil {
		return nil, fmt.Errorf("[NewDG7] error: %w", err)
	}

	rootNode := nodes.NodeByTag(DG7Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG7Tag)
	}

	{
		var numImages int
		{
			tmp := rootNode.NodeByTag(0x02).Value()
			if len(tmp) != 1 {
				return nil, fmt.Errorf("DG7 tag 02 length must be 1 byte (actLen:%1d)", len(tmp))
			}

			numImages = int(tmp[0])

			if (numImages < 1) || (numImages > 9) {
				return nil, fmt.Errorf("DG7 tag 02 must be 1-9 [act:%1d]", numImages)
			}
		}

		for occurrence := 1; occurrence <= numImages; occurrence++ {
			imageBytes := rootNode.NodeByTagOccur(0x5F43, occurrence).Value()

			if !utils.IsImage(imageBytes) {
				return nil, fmt.Errorf("unknown image type [prefixBytes:%x]", utils.SafePrefix(imageBytes, 10))
			}

			out.Images = append(out.Images, DG7Image{Image: slices.Clone(imageBytes)})
		}

	}

	return out, nil
}
