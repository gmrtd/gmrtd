package gmrtd

import (
	"fmt"
	"slices"
)

const DG15Tag = 0x6F

type DG15 struct {
	RawData []byte
}

func NewDG15(data []byte) (*DG15, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *DG15 = new(DG15)

	out.RawData = slices.Clone(data)

	nodes := TlvDecode(out.RawData)

	rootNode := nodes.GetNode(DG15Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG15Tag)
	}

	// TODO - parse the data

	return out, nil
}
