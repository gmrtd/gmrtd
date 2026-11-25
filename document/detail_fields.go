package document

import (
	"bytes"
	"fmt"

	"github.com/gmrtd/gmrtd/mrz"
	"github.com/gmrtd/gmrtd/tlv"
)

func parseDetailFields(root tlv.TlvNode, process func(tlv.TlvTag, tlv.TlvNode) error) error {
	list := bytes.NewReader(root.NodeByTag(0x5C).Value())
	seen := make(map[tlv.TlvTag]bool)
	for list.Len() > 0 {
		tag, err := tlv.ParseTag(list)
		if err != nil {
			return fmt.Errorf("invalid tag in field list: %w", err)
		}
		// Belarus ID cards can list the other-names container instead of the name tag.
		if root.Tag() == DG11Tag && tag == 0xA0 {
			tag = 0x5F0F
		}
		if seen[tag] {
			continue
		}
		seen[tag] = true
		if err := process(tag, root); err != nil {
			return fmt.Errorf("field %x: %w", tag, err)
		}
	}
	return nil
}

func parseDetailNames(root tlv.TlvNode, tag tlv.TlvTag) ([]mrz.MrzName, error) {
	const maxNames = 99
	container := root.NodeByTag(0xA0)
	count := container.NodeByTag(0x02)
	var declared int
	if count.IsValidNode() {
		value := count.Value()
		if len(value) != 1 {
			return nil, fmt.Errorf("tag A0->02 length must be 1 byte (act:%d)", len(value))
		}
		declared = int(value[0])
		if declared < 1 || declared > maxNames {
			return nil, fmt.Errorf("tag A0->02 must be 1-99 (act:%d)", declared)
		}
	} else if root.Tag() == DG11Tag {
		// Some Chinese passports store other names directly under DG11 without a count.
		container = root
	} else {
		return nil, nil
	}

	var names []mrz.MrzName
	for _, child := range container.Children() {
		if child.Tag() != tag {
			continue
		}
		if len(names) == maxNames {
			return nil, fmt.Errorf("more than %d names for tag %x", maxNames, tag)
		}
		name, err := mrz.ParseName(mrz.DecodeValue(string(child.Value())))
		if err != nil {
			return nil, err
		}
		names = append(names, *name)
		if len(names) == declared {
			break
		}
	}
	return names, nil
}
