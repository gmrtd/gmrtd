package gmrtd

import (
	"bytes"
	"fmt"
	"slices"
)

const COMTag = 0x60

// Note: EF.COM is largely deprecated by EF.SOD, to access LDS/Unicode version the helpers on Document
//		 should be used as these will give priority to data within EF.SOD

type COM struct {
	RawData        []byte
	LdsVersion     string
	UnicodeVersion string
	TagList        []TlvTag
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

	// LDS version
	out.LdsVersion = string(rootNode.GetNode(0x5F01).GetValue())
	if len(out.LdsVersion) != 4 {
		return nil, fmt.Errorf("LdsVersion must be 4 characters")
	}

	// Unicode version
	out.UnicodeVersion = string(rootNode.GetNode(0x5F36).GetValue())
	if len(out.UnicodeVersion) != 6 {
		return nil, fmt.Errorf("UnicodeVersion must be 6 characters")
	}

	// Tag list
	{
		tagListBytes := rootNode.GetNode(0x5C).GetValue()
		buf := bytes.NewBuffer(tagListBytes)

		for {
			if buf.Len() <= 0 {
				break
			}

			tag := TlvGetTag(buf)

			out.TagList = append(out.TagList, tag)
		}
	}

	return out, nil
}
