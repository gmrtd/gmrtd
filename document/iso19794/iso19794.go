package iso19794

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/gmrtd/gmrtd/utils"
)

// the following structures are largely borrowed from:
//	https://github.com/paultag/go-cbeff

type ISO19794 struct {
	Facial FacialType `json:"facial,omitempty"`
}

type FacialType struct {
	Header FacialHeader `json:"header"`
	Images []Image      `json:"images,omitempty"`
}

type FacialHeader struct {
	FormatID      [4]byte `json:"formatID,omitempty"`
	VersionID     [4]byte `json:"versionID,omitempty"`
	RecordLength  uint32  `json:"recordLength,omitempty"`
	NumberOfFaces uint16  `json:"numberOfFaces,omitempty"`
}

type Image struct {
	FacialInformation FacialInfo      `json:"facialInformation"`
	Features          []FacialFeature `json:"features,omitempty"`
	ImageInformation  ImageInfo       `json:"imageInformation"`
	Data              []byte          `json:"data,omitempty"`
}

type FacialFeature struct {
	Type       uint8  `json:"type"`
	MajorPoint uint8  `json:"majorPoint"`
	MinorPoint uint8  `json:"minorPoint"`
	X          uint16 `json:"x"`
	Y          uint16 `json:"y"`
	Reserved   uint8  `json:"reserved"`
}

type FacialInfo struct {
	Length          uint32  `json:"length"`
	NumberOfPoints  uint16  `json:"numberOfPoints"`
	Gender          uint8   `json:"gender"`
	EyeColor        uint8   `json:"eyeColor"`
	HairColor       uint8   `json:"hairColor"`
	Properties      [3]byte `json:"properties"`
	Expression      [2]byte `json:"expression"`
	Pose            [3]byte `json:"pose"`
	PoseUncertainty [3]byte `json:"poseUncertainty"`
}

type ImageInfo struct {
	Type       uint8  `json:"type"`
	DataType   uint8  `json:"dataType"`
	Width      uint16 `json:"width"`
	Height     uint16 `json:"height"`
	ColorSpace uint8  `json:"colorSpace"`
	SourceType uint8  `json:"sourceType"`
	DeviceType uint16 `json:"deviceType"`
	Quality    uint16 `json:"quality"`
}

func ProcessISO19794(data []byte) (*ISO19794, error) {
	r := bytes.NewReader(data)

	fh := FacialHeader{}
	{
		if err := binary.Read(r, binary.BigEndian, &fh); err != nil {
			return nil, fmt.Errorf("[processISO19794] binary.Read error: %w", err)
		}
		if !bytes.Equal(fh.FormatID[:], []byte{0x46, 0x41, 0x43, 0}) {
			return nil, fmt.Errorf("[processISO19794] Invalid FacialHeader.FormatID (Act:%x)", fh.FormatID)
		}
	}

	if fh.RecordLength != uint32(len(data)) {
		// NB we've seen slightly different record-lengths in various passports:
		//    - NZ passport: hdr.recordLength = dataLen - 8
		//    - UK passport: hdr.recordLength = dataLen - 1
		// Tolerate small discrepancies (up to 8 bytes), especially given that this is a value-added check
		diff := int(uint32(len(data))) - int(fh.RecordLength)
		if diff < 0 || diff > 8 {
			return nil, fmt.Errorf("[processISO19794] FacialHeader.RecordLength does not match with data (FH.RecordLength:%d) (Data-Len:%d)", fh.RecordLength, len(data))
		}
	}

	var out ISO19794

	out.Facial.Header = fh

	// read images
	for i := 0; i < int(out.Facial.Header.NumberOfFaces); i++ {
		image, err := parseImageIso19794(r)
		if err != nil {
			return nil, fmt.Errorf("[processISO19794] parseImageIso19794(i:%1d) error: %w", i, err)
		}
		out.Facial.Images = append(out.Facial.Images, *image)
	}

	// verify that we read all of the data (or close to it)
	// Note: Some passports have small discrepancies in RecordLength (1-8 bytes), so we tolerate up to 8 bytes remaining
	{
		remaining := r.Len()
		if remaining > 8 {
			return nil, fmt.Errorf("[processISO19794] Too much data remaining: expected at most 8 bytes, got %d", remaining)
		}
	}

	return &out, nil
}

func (ap ISO19794) Images() [][]byte {
	var out [][]byte = make([][]byte, 0)

	for i := range ap.Facial.Images {
		out = append(out, bytes.Clone(ap.Facial.Images[i].Data))
	}

	return out
}

func parseImageIso19794(r *bytes.Reader) (*Image, error) {
	fi := FacialInfo{}
	if err := binary.Read(r, binary.BigEndian, &fi); err != nil {
		return nil, fmt.Errorf("[parseImageIso19794] binary.Read(FacialInfo) error: %w", err)
	}

	features := []FacialFeature{}
	for i := 0; i < int(fi.NumberOfPoints); i++ {
		feature := FacialFeature{}
		if err := binary.Read(r, binary.BigEndian, &feature); err != nil {
			return nil, fmt.Errorf("[parseImageIso19794] binary.Read(FacialFeature:i:%1d) error: %w", i, err)
		}
		features = append(features, feature)
	}

	ii := ImageInfo{}
	if err := binary.Read(r, binary.BigEndian, &ii); err != nil {
		return nil, fmt.Errorf("[parseImageIso19794] binary.Read(ImageInfo) error: %w", err)
	}

	// image-size = fi.Length - FacialInfo [20 bytes] - ImageInfo [12 bytes] - FacialFeatures(s) [* 8 bytes]
	expImageSize := fi.Length - 20 - 12 - (uint32(fi.NumberOfPoints) * 8)
	imageBytes := make([]byte, expImageSize)
	err := binary.Read(r, binary.BigEndian, imageBytes)
	if err != nil {
		return nil, fmt.Errorf("[parseImageIso19794] binary.Read(imageBytes) error: %w", err)
	}

	if !utils.IsImage(imageBytes) {
		return nil, fmt.Errorf("[parseImageIso19794] Unknown image type [prefixBytes:%x]", imageBytes[0:10])
	}

	var img Image = Image{
		FacialInformation: fi,
		ImageInformation:  ii,
		Features:          features,
		Data:              imageBytes,
	}

	return &img, nil
}
