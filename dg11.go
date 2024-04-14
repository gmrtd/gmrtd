package gmrtd

import (
	"fmt"
	"slices"
)

const DG11Tag = 0x6B

type DG11 struct {
	RawData []byte
}

func NewDG11(data []byte) (*DG11, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *DG11 = new(DG11)

	out.RawData = slices.Clone(data)

	nodes := TlvDecode(out.RawData)

	rootNode := nodes.GetNode(DG11Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG11Tag)
	}

	// TODO - parse the data

	return out, nil
}
