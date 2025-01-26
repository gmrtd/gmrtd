package document

import (
	"slices"

	"github.com/gmrtd/gmrtd/tlv"
)

type EfDirApplication struct {
	aid []byte
}

type EFDIR struct {
	RawData     []byte
	Application []EfDirApplication
}

func NewEFDIR(data []byte) *EFDIR {
	if len(data) < 1 {
		return nil
	}

	var out *EFDIR = new(EFDIR)

	out.RawData = slices.Clone(data)

	{
		var nodes *tlv.TlvNodes = tlv.Decode(data)

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

	return out
}
