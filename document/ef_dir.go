package document

import (
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/tlv"
)

type EfDirApplication struct {
	aid []byte
}

type EFDIR struct {
	RawData     []byte             `json:"rawData,omitempty"`
	Application []EfDirApplication `json:"application,omitempty"`
}

func NewEFDIR(data []byte) (efDir *EFDIR, err error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *EFDIR = new(EFDIR)

	out.RawData = slices.Clone(data)

	{
		var nodes *tlv.TlvNodes

		nodes, err = tlv.Decode(data)
		if err != nil {
			return nil, fmt.Errorf("[NewEFDIR] error: %w", err)
		}

		occur := 1
		for {
			node := nodes.GetNodeByOccur(0x61, occur)
			if !node.IsValidNode() {
				break
			}

			out.Application = append(out.Application, EfDirApplication{aid: node.GetNode(0x4F).GetValue()})

			occur++
		}
	}

	return out, nil
}
