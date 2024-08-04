package document

import (
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/tlv"
)

const DG16Tag = 0x70

type DG16 struct {
	RawData []byte
}

func NewDG16(data []byte) (*DG16, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *DG16 = new(DG16)

	out.RawData = slices.Clone(data)

	nodes := tlv.TlvDecode(out.RawData)

	rootNode := nodes.GetNode(DG16Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG16Tag)
	}

	// TODO - parse the data

	return out, nil
}
