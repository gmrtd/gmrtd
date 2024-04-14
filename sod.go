package gmrtd

import (
	"fmt"
	"slices"
)

// TODO - 2 versions of SOD... v1 (preferred) and legacy format v0

const SODTag = 0x77

type SOD struct {
	RawData []byte
	// nodes   *TlvNodes
}

func NewSOD(data []byte) (*SOD, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *SOD = new(SOD)

	out.RawData = slices.Clone(data)

	nodes := TlvDecode(out.RawData)

	rootNode := nodes.GetNode(SODTag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", SODTag)
	}

	// TODO - parse the data

	return out, nil
}
