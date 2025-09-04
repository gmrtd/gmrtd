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

	nodes, err := tlv.Decode(out.RawData)
	if err != nil {
		return nil, fmt.Errorf("[NewDG12] error: %w", err)
	}

	rootNode := nodes.GetNode(DG12Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG12Tag)
	}

	err = out.Details.parseData(rootNode)
	if err != nil {
		return nil, fmt.Errorf("[NewDG12] parseData error: %w", err)
	}

	slog.Debug("DG12", "Details", out.Details)

	return out, nil
}

func (details *DocumentDetails) parseData(node tlv.TlvNode) error {
	tagList, err := tlv.GetTags(bytes.NewBuffer(node.GetNode(0x5C).GetValue()))
	if err != nil {
		return fmt.Errorf("[parseData] GetTags error: %w", err)
	}

	for _, tag := range tagList {
		if err := details.processTag(tag, node); err != nil {
			return fmt.Errorf("[NewDG12] processTag(%x) error: %w", tag, err)
		}
	}

	return nil
}

// processes the 'tag', getting the data from the TLV and populating PersonDetails
func (details *DocumentDetails) processTag(tag tlv.TlvTag, node tlv.TlvNode) error {
	switch tag {
	case 0x5F19:
		details.IssuingAuthority = string(node.GetNode(tag).GetValue())
	case 0x5F26:
		// should be 8 bytes (YYYYMMDD) but we've also seen 4 bytes (BCD) - e.g. Taiwan passport
		details.DateOfIssue = parseDateYYYYMMDD(node.GetNode(tag).GetValue())
	case 0x5F1A:
		// special handling as 'Other Persons' are nested within tag A0 and there can be multiple instances
		numOtherPersons := utils.BytesToInt(node.GetNode(0xA0).GetNode(0x02).GetValue())
		for occur := 1; occur <= numOtherPersons; occur++ {
			tmpName, err := mrz.ParseName(mrz.DecodeValue(string(node.GetNode(0xA0).GetNodeByOccur(tag, occur).GetValue())))
			if err != nil {
				log.Panicf("[processTag] ParseName error: %s", err)
			}

			details.OtherPersons = append(details.OtherPersons, *tmpName)
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
		// should be 14 bytes (YYYYMMDDHHMISS), but probably also have 7 byte BCD encoded variants
		details.PersoDateTime = parseDatetimeYYYYMMDDHHMISS(node.GetNode(tag).GetValue())
	case 0x5F56:
		details.PersoSystemSerialNumber = string(node.GetNode(tag).GetValue())
	default:
		return fmt.Errorf("[processTag] Unsupported Tag:%x", tag)
	}

	return nil
}
