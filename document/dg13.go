package document

import (
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/tlv"
)

// DG13Tag is the tag of the DG13 root data object.
const DG13Tag = 0x6D

// DG13 is data group 13, optional details defined by the issuing state. Its content is
// kept as opaque bytes and is not decoded.
type DG13 struct {
	RawData []byte `json:"rawData,omitempty"`
	Content []byte `json:"content,omitempty"` // contents of the DG (ie within the 6D root tag)
}

// GetRawData returns the raw DG13 bytes as read from the chip.
func (f *DG13) GetRawData() []byte { return f.RawData }

// NewDG13 extracts the content of DG13 from its root tag without decoding it, since some
// issuers do not encode it as valid TLV. It returns nil and no error if data is empty,
// and an error if the root tag cannot be unwrapped.
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
