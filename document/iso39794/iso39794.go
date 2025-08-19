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

func ProcessISO39794_5_AP(data []byte) (*ISO39794_5_AP, error) {
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

func (ap ISO39794_5_AP) GetImages() [][]byte {
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
	Generation int `asn1:"tag:0"`
	Year       int `asn1:"tag:1"`
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
	Year        int `asn1:"tag:0"`
	Month       int `asn1:"tag:1,optional"`
	Day         int `asn1:"tag:2,optional"`
	Hour        int `asn1:"tag:3,optional"`
	Minute      int `asn1:"tag:4,optional"`
	Second      int `asn1:"tag:5,optional"`
	Millisecond int `asn1:"tag:6,optional"`
}

type ISO39794_5_AP struct {
	FaceImageDataBlock FaceImageDataBlockType `asn1:"application,tag:5"`
}

/*
	FaceImageDataBlock ::= [APPLICATION 5] SEQUENCE {
		versionBlock [0] VersionBlock,
		representationBlocks [1] RepresentationBlocks,
		...
	}
*/
type FaceImageDataBlockType struct {
	VersionBlock         VersionBlockType         `asn1:"tag:0"`
	RepresentationBlocks RepresentationBlocksType `asn1:"tag:1"`
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
	RepresentationId      int                      `asn1:"tag:0"`
	ImageRepresentation   ImageRepresentationType  `asn1:"tag:1"`
	CaptureDateTimeBlock  CaptureDateTimeBlockType `asn1:"tag:2,optional"`
	QualityBlocks         GenericBlockType         `asn1:"tag:3,optional"`
	PadDataBlock          GenericBlockType         `asn1:"tag:4,optional"`
	SessionId             int                      `asn1:"tag:5,optional"`
	DerivedFrom           int                      `asn1:"tag:6,optional"`
	CaptureDeviceBlock    CaptureDeviceBlockType   `asn1:"tag:7,optional"`
	IdentityMetadataBlock GenericBlockType         `asn1:"tag:8,optional"`
	LandmarkBlocks        GenericBlockType         `asn1:"tag:9,optional"`
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
	RepresentationData2D    []byte                      `asn1:"tag:0"` // this is the image!
	ImageInformation2DBlock ImageInformation2DBlockType `asn1:"tag:1"`
	CaptureDevice2DBlock    GenericBlockType            `asn1:"tag:2,optional"`
}

/*
	ImageRepresentationBase ::= CHOICE {
		imageRepresentation2DBlock [0] ImageRepresentation2DBlock
	}
*/
type ImageRepresentationBaseType struct {
	ImageRepresentation2DBlock ImageRepresentation2DBlockType `asn1:"tag:0"`
}

/*
	ImageRepresentationExtensionBlock ::= SEQUENCE {
		...
	}
*/
type ImageRepresentationExtensionBlockType struct {
	Raw asn1.RawContent
}

/*
	ImageRepresentation ::= CHOICE {
			base [0] ImageRepresentationBase,
			extensionBlock [1] ImageRepresentationExtensionBlock
		}
*/
type ImageRepresentationType struct {
	Base           ImageRepresentationBaseType           `asn1:"tag:0,optional"`
	ExtensionBlock ImageRepresentationExtensionBlockType `asn1:"tag:1,optional"`
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
	ImageDataFormat                GenericBlockType   `asn1:"tag:0"`
	FaceImageKind2D                GenericBlockType   `asn1:"tag:1,optional"`
	PostAcquisitionProcessingBlock GenericBlockType   `asn1:"tag:2,optional"`
	LossyTransformationAttempts    GenericBlockType   `asn1:"tag:3,optional"`
	CameraToSubjectDistance        int                `asn1:"tag:4,optional"`
	SensorDiagonal                 int                `asn1:"tag:5,optional"`
	LensFocalLength                int                `asn1:"tag:6,optional"`
	ImageSizeBlock                 ImageSizeBlockType `asn1:"tag:7,optional"`
	ImageFaceMeasurementsBlock     GenericBlockType   `asn1:"tag:8,optional"`
	ImageColourSpace               GenericBlockType   `asn1:"tag:9,optional"`
	ReferenceColourMappingBlock    GenericBlockType   `asn1:"tag:10,optional"`
}

/*
	ImageSizeBlock ::= SEQUENCE {
		width [0] ImageSize,
		height [1] ImageSize
	}

ImageSize ::= INTEGER (0..65535)
*/
type ImageSizeBlockType struct {
	Width  int `asn1:"tag:0"`
	Height int `asn1:"tag:1"`
}

/*
RegistryId ::= INTEGER (1..65535)

	RegistryIdBlock ::= SEQUENCE {
		organization		[0] RegistryId,
		id			[1] RegistryId
	}
*/
type RegistryIdBlockType struct {
	Organisation int `asn1:"tag:0"`
	Id           int `asn1:"tag:1"`
}

/*
CertificationIdBlock ::= RegistryIdBlock

CertificationIdBlocks ::= SEQUENCE OF CertificationIdBlock
*/
type CertificationIdBlockType RegistryIdBlockType

type CertificationIdBlocksType struct {
	CertificationIdBlock CertificationIdBlockType
}

/*
	CaptureDeviceBlock ::= SEQUENCE {
		modelIdBlock [0] RegistryIdBlock OPTIONAL,
		certificationIdBlocks [1] CertificationIdBlocks OPTIONAL,
		...
	}
*/
type CaptureDeviceBlockType struct {
	ModelIdBlock          RegistryIdBlockType       `asn1:"tag:0,optional"`
	CertificationIdBlocks CertificationIdBlocksType `asn1:"tag:1,optional"`
}

type GenericBlockType struct {
	Raw asn1.RawContent
}
