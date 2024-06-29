package gmrtd

import (
	"bytes"
	"fmt"
	"log"
	"log/slog"
	"slices"
	"strings"
)

const DG11Tag = 0x6B

// TODO - review parsing (< to space) and < separator on fields
//			- currently we replace '<' with space, unless spec indicates that '<' is used as separator

// TODO - verify data.. e.g. max length.. some fields are mandatory based on others (but example contradicts spec)
//			9303p10 - Table 71. Data Group 11 Tags

type PersonDetails struct {
	NameOfHolder         MrzName
	OtherNames           []MrzName
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

	nodes := TlvDecode(out.RawData)

	slog.Debug("DG11", "TLV", nodes)

	rootNode := nodes.GetNode(DG11Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG11Tag)
	}

	out.Details = parseData(rootNode)

	slog.Debug("DG11", "Details", out.Details)

	return out, nil
}

func parseData(node TlvNode) PersonDetails {
	var out PersonDetails

	tagList := TlvGetTags(bytes.NewBuffer(node.GetNode(0x5C).GetValue()))

	for _, tag := range tagList {
		out.processTag(tag, node)
	}

	return out
}

// processes the 'tag', getting the data from the TLV and populating PersonDetails
func (details *PersonDetails) processTag(tag TlvTag, node TlvNode) {
	switch tag {
	case 0x5F0E:
		details.NameOfHolder = parseName(decodeValue(string(node.GetNode(tag).GetValue())))
	case 0x5F0f:
		// special handling as 'Other Names' are nested within tag A0 and there can be multiple instances
		numOtherNames := bytesToInt(node.GetNode(0xA0).GetNode(0x02).GetValue())
		for occur := 1; occur <= numOtherNames; occur++ {
			details.OtherNames = append(details.OtherNames, parseName(decodeValue(string(node.GetNode(0xA0).GetNodeByOccur(0x5f0f, occur).GetValue()))))
		}
	case 0x5F10:
		details.PersonalNumber = string(node.GetNode(tag).GetValue())
	case 0x5F2B:
		details.FullDateOfBirth = string(node.GetNode(tag).GetValue())
	case 0x5F11:
		details.PlaceOfBirth = strings.Split(string(node.GetNode(tag).GetValue()), "<")
	case 0x5F42:
		details.Address = strings.Split(string(node.GetNode(tag).GetValue()), "<")
	case 0x5F12:
		details.Telephone = string(node.GetNode(tag).GetValue())
	case 0x5F13:
		details.Profession = decodeValue(string(node.GetNode(tag).GetValue()))
	case 0x5F14:
		details.Title = decodeValue(string(node.GetNode(tag).GetValue()))
	case 0x5F15:
		details.PersonalSummary = decodeValue(string(node.GetNode(tag).GetValue()))
	case 0x5F16:
		// image data
		details.ProofOfCitizenship = node.GetNode(tag).GetValue()
	case 0x5F17:
		details.OtherTravelDocuments = strings.Split(string(node.GetNode(tag).GetValue()), "<")
	case 0x5F18:
		details.CustodyInformation = decodeValue(string(node.GetNode(tag).GetValue()))
	default:
		log.Panicf("Unsupported tag:%x", tag)
	}
}
