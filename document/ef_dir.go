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
			node := nodes.NodeByTagOccur(0x61, occur)
			if !node.IsValidNode() {
				break
			}

			tag4f := node.NodeByTag(0x4F)
			if !tag4f.IsValidNode() {
				return nil, fmt.Errorf("[NewEFDIR] Tag 4F(AID) missing (occur:%1d)", occur)
			}

			out.Application = append(out.Application, EfDirApplication{aid: tag4f.Value()})

			occur++
		}
	}

	return out, nil
}
