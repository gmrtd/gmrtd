package document

import (
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/tlv"
)

const DG14Tag = 0x6E

type DG14 struct {
	RawData  []byte
	SecInfos *SecurityInfos
}

func NewDG14(data []byte) (dg14 *DG14, err error) {
	if len(data) < 1 {
		return nil, nil
	}

	dg14 = new(DG14)

	dg14.RawData = slices.Clone(data)

	nodes := tlv.Decode(dg14.RawData)

	rootNode := nodes.GetNode(DG14Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG14Tag)
	}

	if dg14.SecInfos, err = DecodeSecurityInfos(rootNode.GetValue()); err != nil {
		return nil, err
	}

	return dg14, nil
}
