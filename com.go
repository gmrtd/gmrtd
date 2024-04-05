package gmrtd

import (
	"log"
	"slices"
)

type COM struct {
	RawData []byte
	// TODO - could format... e.g. lds/unicode are actually strings... tag-list could be split
	LdsVersion     []byte
	UnicodeVersion []byte
	TagList        []byte
}

func NewCOM(data []byte) *COM {
	if len(data) < 1 {
		return nil
	}

	var out *COM = new(COM)

	out.RawData = slices.Clone(data)

	nodes := TlvDecode(data)

	tag60 := nodes.GetNode(0x60)
	if !tag60.IsValidNode() {
		log.Panicf("EF.COM tag 60 missing")
	}

	out.LdsVersion = tag60.GetNode(0x5F01).GetValue()
	if len(out.LdsVersion) != 4 {
		log.Panicf("EF.COM tag 5f01 (LdsVersion) must be 4 bytes")
	}

	out.UnicodeVersion = tag60.GetNode(0x5F36).GetValue()
	if len(out.UnicodeVersion) != 6 {
		log.Panicf("EF.COM tag 5f36 (UnicodeVersion) must be 6 bytes")
	}

	out.TagList = tag60.GetNode(0x5C).GetValue()

	return out
}
