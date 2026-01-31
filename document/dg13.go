package document

import (
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/tlv"
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
	out.Content, err = tlv.UnwrapTag(DG13Tag, out.RawData)
	if err != nil {
		return nil, fmt.Errorf("[NewDG13] UnwrapTag error: %w", err)
	}

	return out, nil
}
