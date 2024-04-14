package gmrtd

import (
	"fmt"
	"slices"
)

const DG12Tag = 0x6C

type DG12 struct {
	RawData []byte
}

func NewDG12(data []byte) (*DG12, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *DG12 = new(DG12)

	out.RawData = slices.Clone(data)

	nodes := TlvDecode(out.RawData)

	rootNode := nodes.GetNode(DG12Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG12Tag)
	}

	// TODO - parse the data

	return out, nil
}
