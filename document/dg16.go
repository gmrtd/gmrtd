package document

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/gmrtd/gmrtd/mrz"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

const DG16Tag = 0x70

type PersonToNotify struct {
	DateRecorded string
	Name         mrz.MrzName
	Telephone    string
	Address      []string
}

type DG16 struct {
	RawData         []byte
	PersonsToNotify []PersonToNotify
}

func NewDG16(data []byte) (*DG16, error) {
	slog.Debug("NewDG16")

	if len(data) < 1 {
		return nil, nil
	}

	var out *DG16 = new(DG16)

	out.RawData = slices.Clone(data)

	nodes := tlv.Decode(out.RawData)

	rootNode := nodes.GetNode(DG16Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG16Tag)
	}

	out.PersonsToNotify = parseData(rootNode)

	return out, nil
}

func parseData(node tlv.TlvNode) []PersonToNotify {
	var out []PersonToNotify = []PersonToNotify{}

	numTemplates := utils.BytesToInt(node.GetNode(0x2).GetValue())
	if (numTemplates < 1) || (numTemplates > 15) {
		// NB numTemplates must be between 1 and 15 as we construct the tag using 4-bits(0-15).. e.g. 0xA{Occur} (where 'Occur' is 1..15)
		panic(fmt.Sprintf("numTemplates (%1d) must be between 1 and 15(xF)", numTemplates))
	}

	slog.Debug("parseData", "numTemplates", numTemplates)

	for i := 1; i <= numTemplates; i++ {
		slog.Debug("parseData", "loop iteration", i)

		templateTag := tlv.TlvTag(0xA0 + i)
		templateNode := node.GetNode(templateTag)

		if !templateNode.IsValidNode() {
			panic(fmt.Sprintf("template (%02x) expected based on numTemplates tag (%1d)", templateTag, numTemplates))
		}

		out = append(out, parsePersonToNotify(templateNode))
	}

	slog.Debug("parseData", "out", out)

	return out
}

func parsePersonToNotify(node tlv.TlvNode) PersonToNotify {
	var out PersonToNotify

	slog.Debug("parsePersonToNotify", "tlv", node.String())

	// should be 8 bytes (YYYYMMDD), but probably also have 4 byte BCD variants
	out.DateRecorded = parseDateYYYYMMDD(node.GetNode(0x5F50).GetValue())

	out.Name = mrz.ParseName(mrz.DecodeValue(string(node.GetNode(0x5F51).GetValue())))

	out.Telephone = string(node.GetNode(0x5F52).GetValue())

	out.Address = strings.Split(string(node.GetNode(0x5F53).GetValue()), "<")

	slog.Debug("parsePersonToNotify", "out", out)

	return out
}
