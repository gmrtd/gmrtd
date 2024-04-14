package gmrtd

import (
	"fmt"
	"slices"
)

const COMTag = 0x60

type COM struct {
	RawData []byte
	// TODO - could format... e.g. lds/unicode are actually strings... tag-list could be split
	LdsVersion     []byte
	UnicodeVersion []byte
	TagList        []byte
}

func NewCOM(data []byte) (*COM, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *COM = new(COM)

	out.RawData = slices.Clone(data)

	nodes := TlvDecode(out.RawData)

	rootNode := nodes.GetNode(COMTag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", COMTag)
	}

	{
		out.LdsVersion = rootNode.GetNode(0x5F01).GetValue()
		if len(out.LdsVersion) != 4 {
			return nil, fmt.Errorf("EF.COM tag 5f01 (LdsVersion) must be 4 bytes")
		}

		out.UnicodeVersion = rootNode.GetNode(0x5F36).GetValue()
		if len(out.UnicodeVersion) != 6 {
			return nil, fmt.Errorf("EF.COM tag 5f36 (UnicodeVersion) must be 6 bytes")
		}

		out.TagList = rootNode.GetNode(0x5C).GetValue()

	}

	return out, nil
}
