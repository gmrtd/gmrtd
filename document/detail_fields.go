package document

import (
	"bytes"
	"fmt"

	"github.com/gmrtd/gmrtd/mrz"
	"github.com/gmrtd/gmrtd/tlv"
)

// parseDetailFields calls process once for each tag in root's tag list (tag 5C), in list
// order. aliases maps a listed tag to the tag it stands for, so a field listed under both
// names is still processed once.
func parseDetailFields(root tlv.TlvNode, aliases map[tlv.TlvTag]tlv.TlvTag, process func(tlv.TlvTag, tlv.TlvNode) error) error {
	list := bytes.NewReader(root.NodeByTag(0x5C).Value())
	seen := make(map[tlv.TlvTag]bool)
	for list.Len() > 0 {
		tag, err := tlv.ParseTag(list)
		if err != nil {
			return fmt.Errorf("invalid tag in field list: %w", err)
		}
		if alias, ok := aliases[tag]; ok {
			tag = alias
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

// parseDetailNames returns the repeated name field tag, in document order. ICAO Doc 9303
// Part 10 nests these names in a content-specific container: tag A0 holds a count (tag 02,
// one byte, 1-99) followed by that many name fields (Table 71 for DG11 other names; DG12
// other persons use the same structure). Without a count it returns no names, unless
// unwrappedFallback is set, in which case names are read directly from root, up to 99.
func parseDetailNames(root tlv.TlvNode, tag tlv.TlvTag, unwrappedFallback bool) ([]mrz.MrzName, error) {
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
	} else if unwrappedFallback {
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
