package document

// Supports both ISO-19794 and ISO-39794
//
// https://www.christoph-busch.de/files/Busch-ICAO-39794-NFIQ2-210419.pdf
//
// Transition schedule
//	‣ ICAO has adopted its 9303 specification in 2020 and refers now
//	  to ISO/IEC 39794 and its Parts 1, 4 and 5.
//	‣ Passport reader equipment must be able to handle
//    ISO/IEC 39794 data by 2025-01-01 (5 years preparation period).
//	‣ Between 2025 and 2030, passport issuers can use the old version
//    or the new version of standards (5 years transition period).
//
// https://www2023.icao.int/Security/FAL/TRIP/PublishingImages/Pages/Publications/ICAO%20TR%20-%2039794-5%20eMRTD%20Application%20Profile.pdf

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/document/iso19794"
	"github.com/gmrtd/gmrtd/document/iso39794"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

const DG2Tag = 0x75

type DG2 struct {
	RawData []byte                  `json:"rawData,omitempty"`
	Images  []DG2Image              `json:"images,omitempty"`
	BITs    []BiometricInfoTemplate `json:"bits,omitempty"`
}

type DG2Image struct {
	Image []byte `json:"image,omitempty"`
}

type BiometricInfoTemplate struct {
	BHT BiometricHeaderTemplate `json:"bht"`
	BDB BiometricDataBlock      `json:"bdb"`
}

type BiometricHeaderTemplate struct {
	IcaoHeaderVersion []byte `json:"icaoHeaderVersion"` // optional
	BiometricType     []byte `json:"biometricType"`     // optional
	BiometricSubType  []byte `json:"biometricSubType"`  // optional (for DG2)
	CreationDateTime  []byte `json:"creationDateTime"`  // optional
	ValidityPeriod    []byte `json:"validityPeriod"`    // optional
	PID               []byte `json:"pid"`               // optional
	FormatOwner       []byte `json:"formatOwner"`       // required
	FormatType        []byte `json:"formatType"`        // required
}

type BiometricDataBlock struct {
	// NB only one of the following should be present, depending on which biometric encoding is used
	Iso19794 *iso19794.ISO19794      `json:"iso19794,omitempty"`
	Iso39794 *iso39794.ISO39794_5_AP `json:"iso39794,omitempty"`
}

//	75
//		7f61
//			02: 01					** number of images ?
//			7f60
//				a1					** biometric header template
//					80: 0101
//					87: 0101
//					88: 0008
//				5f2e:				** 5F2E or 7F2E

func NewDG2(data []byte) (*DG2, error) {
	if len(data) < 1 {
		return nil, nil
	}

	var out *DG2 = new(DG2)

	out.RawData = slices.Clone(data)

	nodes, err := tlv.Decode(out.RawData)
	if err != nil {
		return nil, fmt.Errorf("[NewDG2] error: %w", err)
	}

	rootNode := nodes.GetNode(DG2Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("[NewDG2] root node (%x) missing", DG2Tag)
	}

	{
		tag7F61 := rootNode.GetNode(0x7f61)
		if !tag7F61.IsValidNode() {
			return nil, fmt.Errorf("[NewDG2] missing tag (7F61)")
		}

		numInstances := utils.BytesToInt(tag7F61.GetNode(0x02).GetValue())
		if (numInstances < 1) || (numInstances > 9) {
			return nil, fmt.Errorf("[NewDG2] numInstances (tag 7f61->02) must be 1-9 (act:%d)", numInstances)
		}

		for occur := 1; occur <= numInstances; occur++ {
			tag7F60 := tag7F61.GetNodeByOccur(0x7f60, occur)
			if !tag7F60.IsValidNode() {
				return nil, fmt.Errorf("[NewDG2] missing tag (7F60) (Occur:%d)", occur)
			}

			tmpBIT, tmpImages, err := out.processBIT(tag7F60)
			if err != nil {
				return nil, fmt.Errorf("[NewDG2] processBIT error: %w", err)
			}

			out.Images = tmpImages
			out.BITs = append(out.BITs, *tmpBIT)
		}
	}

	return out, nil
}

// processes the Biometric Information Template (Tag:7F60)
func (dg2 *DG2) processBIT(node tlv.TlvNode) (*BiometricInfoTemplate, []DG2Image, error) {
	if node.GetTag() != 0x7F60 {
		return nil, nil, fmt.Errorf("[processBIT] Incorrect BIT tag (Exp:7F60) (Act:%x)", node.GetTag())
	}

	var out BiometricInfoTemplate
	var outImages []DG2Image = make([]DG2Image, 0)

	{
		tmpBHT, err := processBHT(node.GetNode(0xA1))
		if err != nil {
			return nil, nil, fmt.Errorf("[processBIT] processBHT error: %w", err)
		}

		out.BHT = *tmpBHT
	}

	/*
	* Proceed based on the underlying biometric encoding
	*
	* Tag 5F2E: ISO-1979-4
	* Tag 7F2E: ISO-39794-5
	 */
	if node.GetNode(0x5F2E).IsValidNode() {
		/*
		* 5F2E -> ISO-1979-4 encoding
		 */
		biometricDataBlock := node.GetNode(0x5F2E).GetValue()

		var err error
		var facial *iso19794.ISO19794

		facial, err = iso19794.ProcessISO19794(biometricDataBlock)
		if err != nil {
			return nil, nil, fmt.Errorf("[processBIT] processISO19794 error: %w", err)
		}

		out.BDB.Iso19794 = facial
		outImages = imageByteArrToDg2ImageArr(facial.GetImages())
	} else if node.GetNode(0x7F2E).IsValidNode() {
		/*
		* 7F2E -> ISO-39794-5 encoding
		 */
		biometricDataBlock := node.GetNode(0x7F2E).GetValue()

		var err error
		var ap *iso39794.ISO39794_5_AP

		ap, err = iso39794.ProcessISO39794_5_AP(biometricDataBlock)
		if err != nil {
			return nil, nil, fmt.Errorf("[processBIT] processISO39794 error: %w", err)
		}

		out.BDB.Iso39794 = ap
		outImages = imageByteArrToDg2ImageArr(ap.GetImages())
	} else {
		return nil, nil, fmt.Errorf("[processBIT] DG2 must have tag 5F2E or 7F2E")
	}

	return &out, outImages, nil
}

// process the Biometric Header Template (BHT) (Tag:A1)
func processBHT(node tlv.TlvNode) (*BiometricHeaderTemplate, error) {
	if node.GetTag() != 0xA1 {
		return nil, fmt.Errorf("[processBHT] Incorrect BHT tag (Exp:A1) (Act:%x)", node.GetTag())
	}

	var out BiometricHeaderTemplate

	out.IcaoHeaderVersion = node.GetNode(0x80).GetValue()
	out.BiometricType = node.GetNode(0x81).GetValue()
	out.BiometricSubType = node.GetNode(0x82).GetValue()
	out.CreationDateTime = node.GetNode(0x83).GetValue()
	out.ValidityPeriod = node.GetNode(0x85).GetValue()
	out.PID = node.GetNode(0x86).GetValue()
	out.FormatOwner = node.GetNode(0x87).GetValue()
	out.FormatType = node.GetNode(0x88).GetValue()

	/*
	* We're current lenient when it comes to missing mandatory fields
	*
	* e.g. Format Owner/Type are mandatory (2 bytes), but we don't actually use for processing
	 */

	return &out, nil
}

func imageByteArrToDg2ImageArr(images [][]byte) []DG2Image {
	var out []DG2Image = make([]DG2Image, 0)

	for i := 0; i < len(images); i++ {
		out = append(out, DG2Image{Image: bytes.Clone(images[i])})
	}

	return out
}
