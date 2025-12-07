package document

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/tlv"
)

const COMTag = 0x60

// Note: EF.COM is largely deprecated by EF.SOD, to access LDS/Unicode version the helpers on Document
//		 should be used as these will give priority to data within EF.SOD

type COM struct {
	RawData        []byte       `json:"rawData,omitempty"`
	LdsVersion     string       `json:"ldsVersion,omitempty"`
	UnicodeVersion string       `json:"unicodeVersion,omitempty"`
	TagList        []tlv.TlvTag `json:"tagList,omitempty"`
}

func NewCOM(data []byte) (*COM, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *COM = new(COM)

	out.RawData = slices.Clone(data)

	nodes, err := tlv.Decode(out.RawData)
	if err != nil {
		return nil, fmt.Errorf("[NewCOM] error: %w", err)
	}

	rootNode := nodes.NodeByTag(COMTag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", COMTag)
	}

	// LDS version
	out.LdsVersion = string(rootNode.NodeByTag(0x5F01).Value())
	if len(out.LdsVersion) != 4 {
		return nil, fmt.Errorf("LdsVersion must be 4 characters")
	}

	// Unicode version
	out.UnicodeVersion = string(rootNode.NodeByTag(0x5F36).Value())
	if len(out.UnicodeVersion) != 6 {
		return nil, fmt.Errorf("UnicodeVersion must be 6 characters")
	}

	// Tag list
	out.TagList, err = tlv.GetTags(bytes.NewBuffer(rootNode.NodeByTag(0x5C).Value()))
	if err != nil {
		return nil, fmt.Errorf("[NewCOM] GetTags error: %w", err)
	}

	return out, nil
}
