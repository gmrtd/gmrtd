package gmrtd

import (
	"fmt"
	"slices"
)

const DG14Tag = 0x6E

type DG14 struct {
	RawData  []byte // TODO - add to test cases (for all other DGs also)
	SecInfos *SecurityInfos
}

func NewDG14(data []byte) (dg14 *DG14, err error) {
	if len(data) < 1 {
		return nil, nil
	}

	dg14 = new(DG14)

	dg14.RawData = slices.Clone(data)

	nodes := TlvDecode(dg14.RawData)

	//log.Printf("DG14 TLV:\n%s", nodes)

	rootNode := nodes.GetNode(DG14Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG14Tag)
	}

	if dg14.SecInfos, err = DecodeSecurityInfos(rootNode.GetValue()); err != nil {
		return nil, err
	}

	//log.Printf("DG14 SecInfos:\n%+v", dg14.SecInfos)

	return dg14, nil
}
