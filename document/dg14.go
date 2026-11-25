package document

import (
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/tlv"
)

// DG14Tag is the tag of the DG14 root data object.
const DG14Tag = 0x6E

// DG14 is data group 14, security options: the SecurityInfos for protocols such as Chip
// Authentication and PACE.
type DG14 struct {
	RawData  []byte         `json:"rawData,omitempty"`
	SecInfos *SecurityInfos `json:"securityInfos,omitempty"`
}

// GetRawData returns the raw DG14 bytes as read from the chip.
func (f *DG14) GetRawData() []byte { return f.RawData }

// NewDG14 parses DG14 and decodes its SecurityInfos. It returns nil and no error if data
// is empty, and an error if the TLV is malformed, the root tag is missing or the
// SecurityInfos cannot be decoded.
func NewDG14(data []byte) (dg14 *DG14, err error) {
	if len(data) < 1 {
		return nil, nil
	}

	dg14 = new(DG14)

	dg14.RawData = slices.Clone(data)

	nodes, err := tlv.Decode(dg14.RawData)
	if err != nil {
		return nil, fmt.Errorf("[NewDG14] error: %w", err)
	}

	rootNode := nodes.NodeByTag(DG14Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG14Tag)
	}

	if dg14.SecInfos, err = DecodeSecurityInfos(rootNode.Value()); err != nil {
		return nil, err
	}

	return dg14, nil
}
