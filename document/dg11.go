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

type PersonDetails struct {
	NameOfHolder         mrz.MrzName   `json:"nameOfHolder,omitempty"`
	OtherNames           []mrz.MrzName `json:"otherNames,omitempty"`
	PersonalNumber       string        `json:"personalNumber,omitempty"`
	FullDateOfBirth      string        `json:"fullDateOfBirth,omitempty"` // YYYYMMDD
	PlaceOfBirth         []string      `json:"placeOfBirth,omitempty"`
	Address              []string      `json:"address,omitempty"`
	Telephone            string        `json:"telephone,omitempty"`
	Profession           string        `json:"profession,omitempty"`
	Title                string        `json:"title,omitempty"`
	PersonalSummary      string        `json:"personalSummary,omitempty"`
	ProofOfCitizenship   []byte        `json:"proofOfCitizenship,omitempty"` // image (ISO-10918)
	OtherTravelDocuments []string      `json:"otherTravelDocuments,omitempty"`
	CustodyInformation   string        `json:"custodyInformation,omitempty"`
}

type DG11 struct {
	RawData []byte        `json:"rawData,omitempty"`
	Details PersonDetails `json:"personDetails,omitempty"`
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

func (details *PersonDetails) processTag5F0F(parentNode tlv.TlvNode) {
	/*
		Expected format as per: Table 71. Data Group 11 Tags (9303 p10)

		Tag 	L 		Value
		‘A0’ 	Var 	Content-specific class
		->	Tag 	L 		Value
		->	‘02’ 	‘01’ 	Number of other names
		->	‘5F0F’ 	Var 	Other name formatted per Doc 9303. The data object repeats as many times as indicated in number of other names (data object with Tag’02’)
	*/

	numOtherNamesNode := parentNode.GetNode(0xA0).GetNode(0x02)

	if numOtherNamesNode.IsValidNode() {
		// special handling as 'Other Names' are nested within tag A0 and there can be multiple instances
		numOtherNames := utils.BytesToInt(numOtherNamesNode.GetValue())

		for occur := 1; occur <= numOtherNames; occur++ {
			details.OtherNames = append(details.OtherNames, mrz.ParseName(mrz.DecodeValue(string(parentNode.GetNode(0xA0).GetNodeByOccur(0x5F0F, occur).GetValue()))))
		}
	} else {
		/*
		* special case handling for non-conformant encodings
		* as we've seen China passports directly using the 5F0F tag
		 */

		// handle any direct instances of the 5F0F tag
		occur := 1
		for {
			otherNameNode := parentNode.GetNodeByOccur(0x5F0F, occur)

			if !otherNameNode.IsValidNode() {
				break
			}

			details.OtherNames = append(details.OtherNames, mrz.ParseName(mrz.DecodeValue(string(otherNameNode.GetValue()))))

			occur++
		}
	}
}

// processes the 'tag', getting the data from the TLV and populating PersonDetails
func (details *PersonDetails) processTag(tag tlv.TlvTag, node tlv.TlvNode) {
	switch tag {
	case 0x5F0E:
		details.NameOfHolder = mrz.ParseName(mrz.DecodeValue(string(node.GetNode(tag).GetValue())))
	case 0x5F0F:
		details.processTag5F0F(node)
	case 0x5F10:
		details.PersonalNumber = string(node.GetNode(tag).GetValue())
	case 0x5F2B:
		// should be 8 bytes (YYYYMMDD) but we've also seen 4 bytes (BCD) - e.g. Malaysia passport
		details.FullDateOfBirth = parseDateYYYYMMDD(node.GetNode(tag).GetValue())
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
