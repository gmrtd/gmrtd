package document

import (
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/tlv"
)

const DG13Tag = 0x6D

type DG13 struct {
	RawData []byte
}

func NewDG13(data []byte) (*DG13, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *DG13 = new(DG13)

	out.RawData = slices.Clone(data)

	nodes := tlv.TlvDecode(out.RawData)

	rootNode := nodes.GetNode(DG13Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG13Tag)
	}

	// TODO - parse the data

	return out, nil
}
