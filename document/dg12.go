package document

import (
	"bytes"
	"fmt"
	"log"
	"log/slog"
	"slices"

	"github.com/gmrtd/gmrtd/mrz"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

const DG12Tag = 0x6C

type DocumentDetails struct {
	IssuingAuthority            string
	DateOfIssue                 string // YYYYMMDD
	OtherPersons                []mrz.MrzName
	EndorsementsAndObservations string
	TaxExitRequirements         string
	ImageFront                  []byte // Image of front of document. Image per ISO/IEC 10918.
	ImageRear                   []byte // Image of read of document. Image per ISO/IEC 10918.
	PersoDateTime               string // yyyymmddhhmmss
	PersoSystemSerialNumber     string
}

type DG12 struct {
	RawData []byte
	Details DocumentDetails
}

func NewDG12(data []byte) (*DG12, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *DG12 = new(DG12)

	out.RawData = slices.Clone(data)

	nodes := tlv.Decode(out.RawData)

	rootNode := nodes.GetNode(DG12Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG12Tag)
	}

	out.Details.parseData(rootNode)

	slog.Debug("DG12", "Details", out.Details)

	return out, nil
}

func (details *DocumentDetails) parseData(node tlv.TlvNode) {
	tagList := tlv.GetTags(bytes.NewBuffer(node.GetNode(0x5C).GetValue()))

	for _, tag := range tagList {
		details.processTag(tag, node)
	}
}

// processes the 'tag', getting the data from the TLV and populating PersonDetails
func (details *DocumentDetails) processTag(tag tlv.TlvTag, node tlv.TlvNode) {
	switch tag {
	case 0x5F19:
		details.IssuingAuthority = string(node.GetNode(tag).GetValue())
	case 0x5F26:
		details.DateOfIssue = string(node.GetNode(tag).GetValue())
	case 0x5F1A:
		// special handling as 'Other Persons' are nested within tag A0 and there can be multiple instances
		numOtherPersons := utils.BytesToInt(node.GetNode(0xA0).GetNode(0x02).GetValue())
		for occur := 1; occur <= numOtherPersons; occur++ {
			details.OtherPersons = append(details.OtherPersons, mrz.ParseName(mrz.DecodeValue(string(node.GetNode(0xA0).GetNodeByOccur(tag, occur).GetValue()))))
		}
	case 0x5F1B:
		details.EndorsementsAndObservations = string(node.GetNode(tag).GetValue())
	case 0x5F1C:
		details.TaxExitRequirements = string(node.GetNode(tag).GetValue())
	case 0x5F1D:
		// image data
		details.ImageFront = node.GetNode(tag).GetValue()
	case 0x5F1E:
		// image data
		details.ImageRear = node.GetNode(tag).GetValue()
	case 0x5F55:
		details.PersoDateTime = string(node.GetNode(tag).GetValue())
	case 0x5F56:
		details.PersoSystemSerialNumber = string(node.GetNode(tag).GetValue())
	default:
		log.Panicf("Unsupported tag:%x", tag)
	}
}
