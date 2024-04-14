package gmrtd

import (
	"fmt"
	"slices"
)

const DG1Tag = 0x61

type DG1 struct {
	RawData []byte
	Mrz     *MRZ
}

func NewDG1(data []byte) (dg1 *DG1, err error) {
	if len(data) < 1 {
		return nil, nil
	}

	dg1 = new(DG1)

	dg1.RawData = slices.Clone(data)

	nodes := TlvDecode(dg1.RawData)

	rootNode := nodes.GetNode(DG1Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG1Tag)
	}

	{
		mrzBytes := rootNode.GetNode(0x5f1f).GetValue()
		if mrzBytes == nil {
			return nil, fmt.Errorf("MRZ Tag (5F1F) missing")
		}

		dg1.Mrz, err = MrzDecode(string(mrzBytes))
		if err != nil {
			return nil, err
		}
	}

	return dg1, nil
}
