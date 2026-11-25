package document

import (
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/mrz"
	"github.com/gmrtd/gmrtd/tlv"
)

// DG12Tag is the tag of the DG12 root data object.
const DG12Tag = 0x6C

// DocumentDetails holds the additional document details from DG12. A field is empty when
// the corresponding data element is absent.
type DocumentDetails struct {
	IssuingAuthority            string        `json:"issuingAuthority,omitempty"`
	DateOfIssue                 string        `json:"dateOfIssue,omitempty"` // YYYYMMDD
	OtherPersons                []mrz.MrzName `json:"otherPersons,omitempty"`
	EndorsementsAndObservations string        `json:"endorsementsAndObservations,omitempty"`
	TaxExitRequirements         string        `json:"taxExitRequirements,omitempty"`
	ImageFront                  []byte        `json:"imageFront,omitempty"`    // Image of front of document. Image per ISO/IEC 10918.
	ImageRear                   []byte        `json:"tmageRear,omitempty"`     // Image of read of document. Image per ISO/IEC 10918.
	PersoDateTime               string        `json:"persoDateTime,omitempty"` // yyyymmddhhmmss
	PersoSystemSerialNumber     string        `json:"persoSystemSerialNumber,omitempty"`
}

// DG12 is data group 12, additional document details.
type DG12 struct {
	RawData []byte          `json:"rawData,omitempty"`
	Details DocumentDetails `json:"documentDetails,omitempty"`
}

// GetRawData returns the raw DG12 bytes as read from the chip.
func (f *DG12) GetRawData() []byte { return f.RawData }

// NewDG12 parses DG12. It returns nil and no error if data is empty, and an error if the
// TLV is malformed, the root tag is missing, the tag list references an unsupported tag
// or a name cannot be parsed. Repeated references in the tag list are processed once.
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

	rootNode := nodes.NodeByTag(DG12Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("[NewDG12] root node (%x) missing", DG12Tag)
	}

	err = parseDetailFields(rootNode, nil, out.Details.processTag)
	if err != nil {
		return nil, fmt.Errorf("[NewDG12] parseData error: %w", err)
	}

	return out, nil
}

// processes the 'tag', getting the data from the TLV and populating PersonDetails
func (details *DocumentDetails) processTag(tag tlv.TlvTag, node tlv.TlvNode) error {
	switch tag {
	case 0x5F19:
		details.IssuingAuthority = string(node.NodeByTag(tag).Value())
	case 0x5F1A:
		names, err := parseDetailNames(node, tag, false)
		details.OtherPersons = names
		return err
	case 0x5F1B:
		details.EndorsementsAndObservations = string(node.NodeByTag(tag).Value())
	case 0x5F1C:
		details.TaxExitRequirements = string(node.NodeByTag(tag).Value())
	case 0x5F1D:
		// image data
		details.ImageFront = node.NodeByTag(tag).Value()
	case 0x5F1E:
		// image data
		details.ImageRear = node.NodeByTag(tag).Value()
	case 0x5F26:
		// should be 8 bytes (YYYYMMDD) but we've also seen 4 bytes (BCD) - e.g. Taiwan passport
		details.DateOfIssue = parseDateYYYYMMDD(node.NodeByTag(tag).Value())
	case 0x5F55:
		// should be 14 bytes (YYYYMMDDHHMISS), but probably also have 7 byte BCD encoded variants
		details.PersoDateTime = parseDatetimeYYYYMMDDHHMISS(node.NodeByTag(tag).Value())
	case 0x5F56:
		details.PersoSystemSerialNumber = string(node.NodeByTag(tag).Value())
	default:
		return fmt.Errorf("[processTag] Unsupported Tag:%x", tag)
	}

	return nil
}
