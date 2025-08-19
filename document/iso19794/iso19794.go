package iso19794

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/gmrtd/gmrtd/utils"
)

// the following structures are largely borrowed from:
//	https://github.com/paultag/go-cbeff

type ISO19794 struct {
	Facial FacialType
}

type FacialType struct {
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
		// NB we've seen a slightly different record-length (NZ passport).. i.e. hdr.recordLength = dataLen - 8
		//	  - tolerate, especially given that this is a value-added check
		if fh.RecordLength != uint32(len(data))-8 {
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

	// verify that we read all of the data
	{
		var byte uint8
		if err := binary.Read(r, binary.BigEndian, &byte); err != io.EOF {
			return nil, fmt.Errorf("[processISO19794] binary.Read: Not all data was consumed (EOF was expected)")
		}
	}

	return &out, nil
}

func (ap ISO19794) GetImages() [][]byte {
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
