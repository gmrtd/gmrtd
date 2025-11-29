package iso39794

import (
	"bytes"
	"encoding/asn1"
	"fmt"

	"github.com/gmrtd/gmrtd/utils"
)

// TODO - the Go ASN1 parser cannot handle CHOICE and seems to be struggling with 'optional' pointer fields
//		  - it may have been easier to just use TLV and manually parse into structs
//			- this way we could properly manage Optional fields and Choice elements!

// TODO - review use of GenericBlockType(placeholder) / asn1.RawValue / asn1.RawContent

func ProcessISO39794p5(data []byte) (*ISO39794_5_AP, error) {
	var ap ISO39794_5_AP

	/*
		{
			// TLV debug
			nodes, _ := tlv.Decode(data)
			log.Printf("TLV:\n\n%s\n\n", nodes.String())
		}
	*/

	var err error

	// parse ASN1
	// NB we ignore any remaining bytes
	_, err = asn1.UnmarshalWithParams(data, &ap, "tag:1")
	if err != nil {
		return nil, fmt.Errorf("[processISO39794_5_AP] asn1 parsing error: %s", err)
	}

	// check we have a valid image
	{
		if len(ap.FaceImageDataBlock.RepresentationBlocks) != 1 {
			return nil, fmt.Errorf("[processISO39794_5_AP] Expected 1 RepresentationBlocks (act:%1d)", len(ap.FaceImageDataBlock.RepresentationBlocks))
		}

		if !utils.IsImage(ap.FaceImageDataBlock.RepresentationBlocks[0].ImageRepresentation.Base.ImageRepresentation2DBlock.RepresentationData2D) {
			return nil, fmt.Errorf("[processISO39794_5_AP] Not a valid image")
		}
	}

	return &ap, nil
}

func (ap ISO39794_5_AP) Images() [][]byte {
	var out [][]byte = make([][]byte, 0)

	for i := range ap.FaceImageDataBlock.RepresentationBlocks {
		out = append(out, bytes.Clone(ap.FaceImageDataBlock.RepresentationBlocks[i].ImageRepresentation.Base.ImageRepresentation2DBlock.RepresentationData2D))
	}

	return out
}

/*
	VersionBlock ::= SEQUENCE {
		generation		[0] VersionGeneration,
		year			[1] VersionYear,
		...
	}
*/
type VersionBlockType struct {
	Generation int `asn1:"tag:0" json:"generation,omitempty"`
	Year       int `asn1:"tag:1" json:"year,omitempty"`
}

/*
CaptureDateTimeBlock ::= DateTimeBlock
*/
type CaptureDateTimeBlockType DateTimeBlockType

/*
	DateTimeBlock ::= SEQUENCE {
		year		[0] Year,
		month		[1] Month		OPTIONAL,
		day			[2] Day			OPTIONAL,
		hour		[3] Hour		OPTIONAL,
		minute		[4] Minute		OPTIONAL,
		second		[5] Second		OPTIONAL,
		millisecond	[6] Millisecond		OPTIONAL
	}
*/
type DateTimeBlockType struct {
	Year        int `asn1:"tag:0" json:"year"`
	Month       int `asn1:"tag:1,optional" json:"month"`
	Day         int `asn1:"tag:2,optional" json:"day"`
	Hour        int `asn1:"tag:3,optional" json:"hour"`
	Minute      int `asn1:"tag:4,optional" json:"minute"`
	Second      int `asn1:"tag:5,optional" json:"second"`
	Millisecond int `asn1:"tag:6,optional" json:"millisecond"`
}

type ISO39794_5_AP struct {
	FaceImageDataBlock FaceImageDataBlockType `asn1:"application,tag:5" json:"faceImageDataBlock"`
}

/*
	FaceImageDataBlock ::= [APPLICATION 5] SEQUENCE {
		versionBlock [0] VersionBlock,
		representationBlocks [1] RepresentationBlocks,
		...
	}
*/
type FaceImageDataBlockType struct {
	VersionBlock         VersionBlockType         `asn1:"tag:0" json:"versionBlock"`
	RepresentationBlocks RepresentationBlocksType `asn1:"tag:1" json:"representationBlocks"`
}

/*
RepresentationBlocks ::= SEQUENCE SIZE (1) OF RepresentationBlock
*/
type RepresentationBlocksType []RepresentationBlockType

/*
	RepresentationBlock ::= SEQUENCE {
		representationId [0] INTEGER (0..MAX),
		imageRepresentation [1] ImageRepresentation,
		captureDateTimeBlock [2] CaptureDateTimeBlock OPTIONAL,
		qualityBlocks [3] QualityBlocks OPTIONAL,
		padDataBlock [4] PADDataBlock OPTIONAL,
		sessionId [5] INTEGER (0..MAX) OPTIONAL,
		derivedFrom [6] INTEGER (0..MAX) OPTIONAL,
		captureDeviceBlock [7] CaptureDeviceBlock OPTIONAL,
		identityMetadataBlock [8] IdentityMetadataBlock OPTIONAL,
		landmarkBlocks [9] LandmarkBlocks OPTIONAL,
		...
	}
*/
type RepresentationBlockType struct {
	RepresentationId      int                      `asn1:"tag:0" json:"representationId"`
	ImageRepresentation   ImageRepresentationType  `asn1:"tag:1" json:"imageRepresentation"`
	CaptureDateTimeBlock  CaptureDateTimeBlockType `asn1:"tag:2,optional" json:"captureDateTimeBlock"`
	QualityBlocks         GenericBlockType         `asn1:"tag:3,optional" json:"qualityBlocks"`
	PadDataBlock          GenericBlockType         `asn1:"tag:4,optional" json:"padDataBlock"`
	SessionId             int                      `asn1:"tag:5,optional" json:"sessionId"`
	DerivedFrom           int                      `asn1:"tag:6,optional" json:"derivedFrom"`
	CaptureDeviceBlock    CaptureDeviceBlockType   `asn1:"tag:7,optional" json:"captureDeviceBlock"`
	IdentityMetadataBlock GenericBlockType         `asn1:"tag:8,optional" json:"identityMetadataBlock"`
	LandmarkBlocks        GenericBlockType         `asn1:"tag:9,optional" json:"landmarkBlocks"`
}

/*
	ImageRepresentation2DBlock ::= SEQUENCE {
		representationData2D [0] OCTET STRING,
		imageInformation2DBlock [1] ImageInformation2DBlock,
		captureDevice2DBlock [2] CaptureDevice2DBlock OPTIONAL,
		...
	}
*/
type ImageRepresentation2DBlockType struct {
	RepresentationData2D    []byte                      `asn1:"tag:0" json:"representationData2D"` // this is the image!
	ImageInformation2DBlock ImageInformation2DBlockType `asn1:"tag:1" json:"imageInformation2DBlock"`
	CaptureDevice2DBlock    GenericBlockType            `asn1:"tag:2,optional" json:"captureDevice2DBlock"`
}

/*
	ImageRepresentationBase ::= CHOICE {
		imageRepresentation2DBlock [0] ImageRepresentation2DBlock
	}
*/
type ImageRepresentationBaseType struct {
	ImageRepresentation2DBlock ImageRepresentation2DBlockType `asn1:"tag:0" json:"imageRepresentation2DBlock"`
}

/*
	ImageRepresentationExtensionBlock ::= SEQUENCE {
		...
	}
*/
type ImageRepresentationExtensionBlockType struct {
	Raw asn1.RawContent `json:"raw"`
}

/*
	ImageRepresentation ::= CHOICE {
			base [0] ImageRepresentationBase,
			extensionBlock [1] ImageRepresentationExtensionBlock
		}
*/
type ImageRepresentationType struct {
	Base           ImageRepresentationBaseType           `asn1:"tag:0,optional" json:"base"`
	ExtensionBlock ImageRepresentationExtensionBlockType `asn1:"tag:1,optional" json:"extensionBlock"`
}

/*
	ImageInformation2DBlock ::= SEQUENCE {
		imageDataFormat [0] ImageDataFormat,
		faceImageKind2D [1] FaceImageKind2D OPTIONAL,
		postAcquisitionProcessingBlock [2] PostAcquisitionProcessingBlock OPTIONAL,
		lossyTransformationAttempts [3] LossyTransformationAttempts OPTIONAL,
		cameraToSubjectDistance [4] CameraToSubjectDistance OPTIONAL,
		sensorDiagonal [5] SensorDiagonal OPTIONAL,
		lensFocalLength [6] LensFocalLength OPTIONAL,
		imageSizeBlock [7] ImageSizeBlock OPTIONAL,
		imageFaceMeasurementsBlock [8] ImageFaceMeasurementsBlock OPTIONAL,
		imageColourSpace [9] ImageColourSpace OPTIONAL,
		referenceColourMappingBlock [10] ReferenceColourMappingBlock OPTIONAL,
		...
	}
*/
type ImageInformation2DBlockType struct {
	ImageDataFormat                GenericBlockType   `asn1:"tag:0" json:"imageDataFormat"`
	FaceImageKind2D                GenericBlockType   `asn1:"tag:1,optional" json:"faceImageKind2D"`
	PostAcquisitionProcessingBlock GenericBlockType   `asn1:"tag:2,optional" json:"postAcquisitionProcessingBlock"`
	LossyTransformationAttempts    GenericBlockType   `asn1:"tag:3,optional" json:"lossyTransformationAttempts"`
	CameraToSubjectDistance        int                `asn1:"tag:4,optional" json:"cameraToSubjectDistance"`
	SensorDiagonal                 int                `asn1:"tag:5,optional" json:"sensorDiagonal"`
	LensFocalLength                int                `asn1:"tag:6,optional" json:"lensFocalLength"`
	ImageSizeBlock                 ImageSizeBlockType `asn1:"tag:7,optional" json:"imageSizeBlock"`
	ImageFaceMeasurementsBlock     GenericBlockType   `asn1:"tag:8,optional" json:"imageFaceMeasurementsBlock"`
	ImageColourSpace               GenericBlockType   `asn1:"tag:9,optional" json:"imageColourSpace"`
	ReferenceColourMappingBlock    GenericBlockType   `asn1:"tag:10,optional" json:"referenceColourMappingBlock"`
}

/*
	ImageSizeBlock ::= SEQUENCE {
		width [0] ImageSize,
		height [1] ImageSize
	}

ImageSize ::= INTEGER (0..65535)
*/
type ImageSizeBlockType struct {
	Width  int `asn1:"tag:0" json:"width"`
	Height int `asn1:"tag:1" json:"height"`
}

/*
RegistryId ::= INTEGER (1..65535)

	RegistryIdBlock ::= SEQUENCE {
		organization		[0] RegistryId,
		id			[1] RegistryId
	}
*/
type RegistryIdBlockType struct {
	Organisation int `asn1:"tag:0" json:"organisation"`
	Id           int `asn1:"tag:1" json:"id"`
}

/*
CertificationIdBlock ::= RegistryIdBlock

CertificationIdBlocks ::= SEQUENCE OF CertificationIdBlock
*/
type CertificationIdBlockType RegistryIdBlockType

type CertificationIdBlocksType struct {
	CertificationIdBlock CertificationIdBlockType `json:"certificationIdBlock"`
}

/*
	CaptureDeviceBlock ::= SEQUENCE {
		modelIdBlock [0] RegistryIdBlock OPTIONAL,
		certificationIdBlocks [1] CertificationIdBlocks OPTIONAL,
		...
	}
*/
type CaptureDeviceBlockType struct {
	ModelIdBlock          RegistryIdBlockType       `asn1:"tag:0,optional" json:"modelIdBlock"`
	CertificationIdBlocks CertificationIdBlocksType `asn1:"tag:1,optional" json:"certificationIdBlocks"`
}

type GenericBlockType struct {
	Raw asn1.RawContent `json:"raw"`
}
