package document

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

const DG13Tag = 0x6D

type DG13 struct {
	RawData []byte
	Content []byte // contents of the DG (ie within the 6D root tag)
}

func NewDG13(data []byte) (*DG13, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *DG13 = new(DG13)

	out.RawData = slices.Clone(data)

	// extract the content from the root tag (6D)
	// NB content may not be TLV, so don't attempt to decode everything
	//		- we've seen some bad TLV encoding within DG13 on SG passports
	{
		// extract length (of parent tag) to determine file size
		tmpBuf := bytes.NewBuffer(out.RawData)

		tag := tlv.GetTag(tmpBuf)
		if DG13Tag != tag {
			return nil, fmt.Errorf("(NewDG13) invalid root tag (Exp:%x, Act:%x)", DG13Tag, tag)
		}

		len := int(tlv.GetLength(tmpBuf))

		out.Content = utils.GetBytesFromBuffer(tmpBuf, len)
	}

	return out, nil
}
