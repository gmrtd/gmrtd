package gmrtd

// TODO - need to support ISO 39794 going forward (currently ISO 19794-1:2005)
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

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"slices"
)

const DG2Tag = 0x75

type DG2 struct {
	RawData []byte
	BITs    []BiometricInfoTemplate
}

type BiometricInfoTemplate struct {
	BHT BiometricHeaderTemplate
	BDB BiometricDataBlock
}

type BiometricHeaderTemplate struct {
	IcaoHeaderVersion []byte // optional
	BiometricType     []byte // optional
	BiometricSubType  []byte // optional (for DG2)
	CreationDateTime  []byte // optional
	ValidityPeriod    []byte // optional
	PID               []byte // optional
	FormatOwner       []byte // required
	FormatType        []byte // required
}

type BiometricDataBlock struct {
	Facial Facial
}

// the following structures are largely borrowed from:
//	https://github.com/paultag/go-cbeff

type Facial struct {
	Header FacialHeader
	Images []Image
}

type FacialHeader struct {
	FormatID      [4]byte
	VersionID     [4]byte
	RecordLength  uint32
	NumberOfFaces uint16
}

type Image struct {
	FacialInformation FacialInfo
	Features          []FacialFeature
	ImageInformation  ImageInfo
	Data              []byte
}

type FacialFeature struct {
	Type       uint8
	MajorPoint uint8
	MinorPoint uint8
	X          uint16
	Y          uint16
	Reserved   uint8
}

type FacialInfo struct {
	Length          uint32
	NumberOfPoints  uint16
	Gender          uint8
	EyeColor        uint8
	HairColor       uint8
	Properties      [3]byte
	Expression      [2]byte
	Pose            [3]byte
	PoseUncertainty [3]byte
}

type ImageInfo struct {
	Type       uint8
	DataType   uint8
	Width      uint16
	Height     uint16
	ColorSpace uint8
	SourceType uint8
	DeviceType uint16
	Quality    uint16
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

	nodes := TlvDecode(out.RawData)

	rootNode := nodes.GetNode(DG2Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG2Tag)
	}

	{
		tag7F61 := rootNode.GetNode(0x7f61)
		if !tag7F61.IsValidNode() {
			return nil, fmt.Errorf("missing tag (7F61)")
		}

		numInstances := bytesToInt(tag7F61.GetNode(0x02).GetValue())
		if (numInstances < 1) || (numInstances > 9) {
			return nil, fmt.Errorf("numInstances (tag 7f61->02) must be 1-9 (act:%d)", numInstances)
		}

		for occur := 1; occur <= numInstances; occur++ {
			tag7F60 := tag7F61.GetNodeByOccur(0x7f60, 1)
			if !tag7F60.IsValidNode() {
				return nil, fmt.Errorf("missing tag (7F60) (Occur:%d)", occur)
			}

			out.BITs = append(out.BITs, out.processBIT(tag7F60))
		}
	}

	return out, nil
}

// processes the Biometric Information Template (Tag:7F60)
func (dg2 *DG2) processBIT(node TlvNode) BiometricInfoTemplate {
	if node.GetTag() != 0x7F60 {
		log.Panicf("Incorrect BIT tag (Exp:7F60) (Act:%x)", node.GetTag())
	}

	var out BiometricInfoTemplate

	out.BHT = processBHT(node.GetNode(0xA1))

	{
		// tag 5F2E or 7F2E
		biometricDataBlock := node.GetNode(0x5F2E).GetValue()
		if biometricDataBlock == nil {
			biometricDataBlock = node.GetNode(0x7F2E).GetValue()
		}
		if biometricDataBlock == nil {
			log.Panicf("DG2 must have tag 5F2E or 7F2E")
		}

		var err error
		var facial *Facial
		// TODO - currently assume 19794.. but also need to handle 39794 going forward
		facial, err = processISO19794(biometricDataBlock)
		if err != nil {
			log.Panic(err)
		}
		out.BDB.Facial = *facial
	}

	return out
}

// process the Biometric Header Template (BHT) (Tag:A1)
func processBHT(node TlvNode) BiometricHeaderTemplate {
	if node.GetTag() != 0xA1 {
		log.Panicf("Incorrect BHT tag (Exp:A1) (Act:%x)", node.GetTag())
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

	// TODO - Format Owner / Type are mandatory and each have length=2

	return out
}

func processISO19794(data []byte) (*Facial, error) {
	r := bytes.NewReader(data)

	fh := FacialHeader{}
	{
		if err := binary.Read(r, binary.BigEndian, &fh); err != nil {
			return nil, err
		}
		if !bytes.Equal(fh.FormatID[:], []byte{0x46, 0x41, 0x43, 0}) {
			log.Panicf("Invalid FacialHeader.FormatID (Act:%x)", fh.FormatID)
		}
	}

	if fh.RecordLength != uint32(len(data)) {
		log.Panicf("FacialHeader.RecordLength does not match with data (FH.RecordLength:%d) (Data-Len:%d)", fh.RecordLength, len(data))
	}

	var facial Facial

	facial.Header = fh

	// read images
	for i := 0; i < int(facial.Header.NumberOfFaces); i++ {
		image, err := parseISO19794_Image(r)
		if err != nil {
			log.Panic(err)
		}
		facial.Images = append(facial.Images, *image)
	}

	// verify that we read all of the data
	{
		var byte uint8
		if err := binary.Read(r, binary.BigEndian, &byte); err != io.EOF {
			log.Panicf("No all data consumed (EOF was expected)")
		}
	}

	return &facial, nil
}

func parseISO19794_Image(r *bytes.Reader) (*Image, error) {
	fi := FacialInfo{}
	if err := binary.Read(r, binary.BigEndian, &fi); err != nil {
		return nil, err
	}

	features := []FacialFeature{}
	for i := 0; i < int(fi.NumberOfPoints); i++ {
		feature := FacialFeature{}
		if err := binary.Read(r, binary.BigEndian, &feature); err != nil {
			return nil, err
		}
		features = append(features, feature)
	}

	ii := ImageInfo{}
	if err := binary.Read(r, binary.BigEndian, &ii); err != nil {
		return nil, err
	}

	// image-size = fi.Length - FacialInfo [20 bytes] - ImageInfo [12 bytes] - FacialFeatures(s) [* 8 bytes]
	expImageSize := fi.Length - 20 - 12 - (uint32(fi.NumberOfPoints) * 8)
	imageBytes := make([]byte, expImageSize)
	err := binary.Read(r, binary.BigEndian, imageBytes)
	if err != nil {
		return nil, err
	}

	if !isImage(imageBytes) {
		log.Panicf("Unknown image type [prefixBytes:%x]", imageBytes[0:10])
	}

	var img Image = Image{
		FacialInformation: fi,
		ImageInformation:  ii,
		Features:          features,
		Data:              imageBytes,
	}

	return &img, nil
}
