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
	DateRecorded string       `json:"dateRecorded,omitempty"`
	Name         *mrz.MrzName `json:"name,omitempty"`
	Telephone    string       `json:"telephone,omitempty"`
	Address      []string     `json:"address,omitempty"`
}

type DG16 struct {
	RawData         []byte           `json:"rawData,omitempty"`
	PersonsToNotify []PersonToNotify `json:"personsToNotify,omitempty"`
}

func NewDG16(data []byte) (*DG16, error) {
	slog.Debug("NewDG16")

	if len(data) < 1 {
		return nil, nil
	}

	var out *DG16 = new(DG16)

	out.RawData = slices.Clone(data)

	nodes, err := tlv.Decode(out.RawData)
	if err != nil {
		return nil, fmt.Errorf("[NewDG16] error: %w", err)
	}

	rootNode := nodes.GetNode(DG16Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG16Tag)
	}

	out.PersonsToNotify, err = parseData(rootNode)
	if err != nil {
		return nil, fmt.Errorf("[NewDG16] parseData error: %w", err)
	}

	return out, nil
}

func parseData(node tlv.TlvNode) ([]PersonToNotify, error) {
	var out []PersonToNotify = []PersonToNotify{}

	numTemplates := utils.BytesToInt(node.GetNode(0x2).GetValue())
	if (numTemplates < 1) || (numTemplates > 15) {
		// NB numTemplates must be between 1 and 15 as we construct the tag using 4-bits(0-15).. e.g. 0xA{Occur} (where 'Occur' is 1..15)
		return nil, fmt.Errorf("[parseData] numTemplates (%1d) must be between 1 and 15(xF)", numTemplates)
	}

	slog.Debug("parseData", "numTemplates", numTemplates)

	for i := 1; i <= numTemplates; i++ {
		slog.Debug("parseData", "loop iteration", i)

		templateTag := tlv.TlvTag(0xA0 + i)
		templateNode := node.GetNode(templateTag)

		if !templateNode.IsValidNode() {
			return nil, fmt.Errorf("[parseData] template (%02x) expected based on numTemplates tag (%1d)", templateTag, numTemplates)
		}

		personToNotify, err := parsePersonToNotify(templateNode)
		if err != nil {
			return nil, fmt.Errorf("[parseData] parsePersonToNotify error: %w", err)
		}

		out = append(out, *personToNotify)
	}

	slog.Debug("parseData", "out", out)

	return out, nil
}

func parsePersonToNotify(node tlv.TlvNode) (*PersonToNotify, error) {
	var err error
	var out PersonToNotify

	slog.Debug("parsePersonToNotify", "tlv", node.String())

	// should be 8 bytes (YYYYMMDD), but probably also have 4 byte BCD variants
	out.DateRecorded = parseDateYYYYMMDD(node.GetNode(0x5F50).GetValue())

	out.Name, err = mrz.ParseName(mrz.DecodeValue(string(node.GetNode(0x5F51).GetValue())))
	if err != nil {
		return nil, fmt.Errorf("[parsePersonToNotify] mrz.ParseName error: %w", err)
	}

	out.Telephone = string(node.GetNode(0x5F52).GetValue())

	out.Address = strings.Split(string(node.GetNode(0x5F53).GetValue()), "<")

	slog.Debug("parsePersonToNotify", "out", out)

	return &out, nil
}
