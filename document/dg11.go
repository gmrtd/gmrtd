package document

import (
	"bytes"
	"fmt"
	"log"
	"log/slog"
	"slices"
	"strings"

	"github.com/gmrtd/gmrtd/mrz"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

const DG11Tag = 0x6B

// TODO - review parsing (< to space) and < separator on fields
//			- currently we replace '<' with space, unless spec indicates that '<' is used as separator

// TODO - verify data.. e.g. max length.. some fields are mandatory based on others (but example contradicts spec)
//			9303p10 - Table 71. Data Group 11 Tags

type PersonDetails struct {
	NameOfHolder         mrz.MrzName
	OtherNames           []mrz.MrzName
	PersonalNumber       string
	FullDateOfBirth      string // YYYYMMDD
	PlaceOfBirth         []string
	Address              []string
	Telephone            string
	Profession           string
	Title                string
	PersonalSummary      string
	ProofOfCitizenship   []byte // image (ISO-10918)
	OtherTravelDocuments []string
	CustodyInformation   string
}

type DG11 struct {
	RawData []byte
	Details PersonDetails
}

func NewDG11(data []byte) (*DG11, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *DG11 = new(DG11)

	out.RawData = slices.Clone(data)

	nodes := tlv.Decode(out.RawData)

	slog.Debug("DG11", "TLV", nodes)

	rootNode := nodes.GetNode(DG11Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG11Tag)
	}

	out.Details.parseData(rootNode)

	slog.Debug("DG11", "Details", out.Details)

	return out, nil
}

func (details *PersonDetails) parseData(node tlv.TlvNode) {
	tagList := tlv.GetTags(bytes.NewBuffer(node.GetNode(0x5C).GetValue()))

	for _, tag := range tagList {
		details.processTag(tag, node)
	}
}

// processes the 'tag', getting the data from the TLV and populating PersonDetails
func (details *PersonDetails) processTag(tag tlv.TlvTag, node tlv.TlvNode) {
	switch tag {
	case 0x5F0E:
		details.NameOfHolder = mrz.ParseName(mrz.DecodeValue(string(node.GetNode(tag).GetValue())))
	case 0x5F0F:
		// TODO - not parsing for china... is it because we're expecting more complex encoding, as below....
		//			- china just seems to be encoding this as a regular name field (i.e. 1 name)

		// special handling as 'Other Names' are nested within tag A0 and there can be multiple instances
		numOtherNames := utils.BytesToInt(node.GetNode(0xA0).GetNode(0x02).GetValue())
		for occur := 1; occur <= numOtherNames; occur++ {
			details.OtherNames = append(details.OtherNames, mrz.ParseName(mrz.DecodeValue(string(node.GetNode(0xA0).GetNodeByOccur(tag, occur).GetValue()))))
		}
	case 0x5F10:
		details.PersonalNumber = string(node.GetNode(tag).GetValue())
	case 0x5F2B:
		// TODO - observed as BCD on MY passport.. 5f2b: 19920115 (i.e. 4 bytes instead of 8)
		//			- similar issue could exist for other fields
		details.FullDateOfBirth = string(node.GetNode(tag).GetValue())
	case 0x5F11:
		details.PlaceOfBirth = strings.Split(string(node.GetNode(tag).GetValue()), "<")
	case 0x5F42:
		details.Address = strings.Split(string(node.GetNode(tag).GetValue()), "<")
	case 0x5F12:
		details.Telephone = string(node.GetNode(tag).GetValue())
	case 0x5F13:
		details.Profession = mrz.DecodeValue(string(node.GetNode(tag).GetValue()))
	case 0x5F14:
		details.Title = mrz.DecodeValue(string(node.GetNode(tag).GetValue()))
	case 0x5F15:
		details.PersonalSummary = mrz.DecodeValue(string(node.GetNode(tag).GetValue()))
	case 0x5F16:
		// image data
		details.ProofOfCitizenship = node.GetNode(tag).GetValue()
	case 0x5F17:
		details.OtherTravelDocuments = strings.Split(string(node.GetNode(tag).GetValue()), "<")
	case 0x5F18:
		details.CustodyInformation = mrz.DecodeValue(string(node.GetNode(tag).GetValue()))
	default:
		log.Panicf("Unsupported tag:%x", tag)
	}
}
