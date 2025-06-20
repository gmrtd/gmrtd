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
	RawData []byte `json:"rawData,omitempty"`
	Content []byte `json:"content,omitempty"` // contents of the DG (ie within the 6D root tag)
}

func NewDG13(data []byte) (out *DG13, err error) {
	if len(data) < 1 {
		return nil, nil
	}

	out = new(DG13)

	out.RawData = slices.Clone(data)

	// extract the content from the root tag (6D)
	// NB content may not be TLV, so don't attempt to decode everything
	//		- we've seen some bad TLV encoding within DG13 on SG passports
	{
		// extract length (of parent tag) to determine file size
		tmpBuf := bytes.NewBuffer(out.RawData)

		tag, err := tlv.GetTag(tmpBuf)
		if err != nil {
			return nil, fmt.Errorf("[NewDG13] GetTag error: %w", err)
		}
		if DG13Tag != tag {
			return nil, fmt.Errorf("(NewDG13) invalid root tag (Exp:%x, Act:%x)", DG13Tag, tag)
		}

		var tmpTlvLength tlv.TlvLength

		tmpTlvLength, err = tlv.GetLength(tmpBuf)
		if err != nil {
			return nil, fmt.Errorf("[NewDG13] GetLength error: %w", err)
		}
		len := int(tmpTlvLength)

		out.Content, err = utils.GetBytesFromBuffer(tmpBuf, len)
		if err != nil {
			return nil, fmt.Errorf("[NewDG13] ByteBuffer error: %w", err)
		}
	}

	return out, nil
}
