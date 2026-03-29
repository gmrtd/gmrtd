package document

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/gmrtd/gmrtd/mrz"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

func TestNewDG12NoData(t *testing.T) {
	if dg12, err := NewDG12(nil); dg12 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if dg12, err := NewDG12([]byte{}); dg12 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewDG12BadTlv(t *testing.T) {
	var dg12bytes []byte = utils.HexToBytes("02101234") // invalid TLV encoding - insufficient bytes

	dg12, err := NewDG12(dg12bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg12 != nil {
		t.Errorf("DG not expected for error case")
	}
}

func TestNewDG12UnhappyRootTag(t *testing.T) {
	var dg12bytes []byte = utils.HexToBytes("01021234") // valid TLV but invalid DG12, as tag 6C is missing

	dg12, err := NewDG12(dg12bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg12 != nil {
		t.Errorf("DG12 not expected for error case")
	}
}

func TestNewDG12NZ(t *testing.T) {
	// Adapted from NZ passport (with data changed)
	//
	// 6C205C045F555F565F550E32303136313131353031333631325F56064E2D34393632
	//
	//	6c
	// 		5c: 5f555f56 [_U_V]
	// 		5f55: 3230313631313135303133363132 [20161115013612]
	// 		5f56: 4e2d34393632 [N-4962]

	var dg12bytes []byte = utils.HexToBytes("6C205C045F555F565F550E32303136313131353031333631325F56064E2D34393632")

	var expDetails DocumentDetails = DocumentDetails{PersoDateTime: "20161115013612", PersoSystemSerialNumber: "N-4962"}

	var doc Document

	err := doc.NewDG(12, dg12bytes)

	if err != nil {
		t.Errorf("Error not expected")
	}

	if doc.Mf.Lds1.Dg12 == nil {
		t.Errorf("DG12 expected")
	}

	if !reflect.DeepEqual(doc.Mf.Lds1.Dg12.Details, expDetails) {
		t.Errorf("DG12 DocumentDetails differs to expected\n(Act:%+v)\n(Exp:%+v)", doc.Mf.Lds1.Dg12.Details, expDetails)
	}
}

func TestNewDG12FR(t *testing.T) {
	// From FR passport (does NOT contain any PII)
	//
	// 6C3E5C045F195F265F192A4A414B41525441202D20414D42415353414445204445204652414E434520454E20494E444F4E455349455F26083230313730393035
	//
	// 6c
	//		5c: 5f195f26
	//		5f19: 4a414b41525441202d20414d42415353414445204445204652414e434520454e20494e444f4e45534945 [JAKARTA - AMBASSADE DE FRANCE EN INDONESIE]
	//		5f26: 3230313730393035 [20170905]
	//
	// IssuingAuthority           : JAKARTA - AMBASSADE DE FRANCE EN INDONESIE
	// DateOfIssue                : 20170905
	// OtherPersons               : []
	// EndorsementsAndObservations:
	// TaxExitRequirements        :
	// ImageFront                 :
	// ImageRear                  :
	// PersoDateTime              :
	// PersoSystemSerialNumber    :

	var dg12bytes []byte = utils.HexToBytes("6C3E5C045F195F265F192A4A414B41525441202D20414D42415353414445204445204652414E434520454E20494E444F4E455349455F26083230313730393035")

	var expDetails DocumentDetails = DocumentDetails{IssuingAuthority: "JAKARTA - AMBASSADE DE FRANCE EN INDONESIE", DateOfIssue: "20170905"}

	var doc Document

	err := doc.NewDG(12, dg12bytes)

	if err != nil {
		t.Errorf("Error not expected")
	}

	if doc.Mf.Lds1.Dg12 == nil {
		t.Errorf("DG12 expected")
	}

	if !reflect.DeepEqual(doc.Mf.Lds1.Dg12.Details, expDetails) {
		t.Errorf("DG12 DocumentDetails differs to expected\n(Act:%+v)\n(Exp:%+v)", doc.Mf.Lds1.Dg12.Details, expDetails)
	}
}

func TestNewDG12TagsErr(t *testing.T) {
	// NB incomplete tag (5F..)
	var dg12bytes []byte = utils.HexToBytes("6C035C015F")

	var doc Document

	err := doc.NewDG(12, dg12bytes)

	if err == nil {
		t.Errorf("expected error")
	}

	if doc.Mf.Lds1.Dg12 != nil {
		t.Errorf("DG12 NOT expected")
	}
}

func TestNewDG12UnknownTagErr(t *testing.T) {
	// NB unsupported tag (5F00)
	var dg12bytes []byte = utils.HexToBytes("6C045C025F00")

	var doc Document

	err := doc.NewDG(12, dg12bytes)

	if err == nil {
		t.Errorf("expected error")
	}

	if doc.Mf.Lds1.Dg12 != nil {
		t.Errorf("DG12 NOT expected")
	}
}

func TestProcessTag(t *testing.T) {
	testCases := []struct {
		name          string
		tlvTag        tlv.TlvTag
		tlvNode       tlv.TlvNode
		expDocDetails DocumentDetails
	}{
		{
			// 5F19: "UNITED STATES DEPARTMENT OF STATE"
			name:          "5F19 IssuingAuthority",
			tlvTag:        0x5F19,
			tlvNode:       tlv.NewTlvConstructedNode(0x6C).AddChild(tlv.NewTlvSimpleNode(0x5F19, utils.HexToBytes("554E4954454420535441544553204445504152544D454E54204F46205354415445"))),
			expDocDetails: DocumentDetails{IssuingAuthority: "UNITED STATES DEPARTMENT OF STATE"},
		},
		{
			// 5F1A: OtherPersons: [1] SMITH, BRENDA P
			//
			// - sample taken from 'SUPPLEMENT to Doc 9303' (Release 11)
			//
			// 		‘6C’ ‘45’
			//			...
			// 			‘0A’ ‘15’
			// 				‘02’ ‘01’ ‘01’
			// 				‘5F1A’ ‘0F’ SMITH<<BRENDA<P
			name:          "5F1A OtherPersons",
			tlvTag:        0x5F1A,
			tlvNode:       tlv.NewTlvConstructedNode(0x6C).AddChild(tlv.NewTlvConstructedNode(0xA0).AddChild(tlv.NewTlvSimpleNode(0x02, []byte{0x01})).AddChild(tlv.NewTlvSimpleNode(0x5F1A, utils.HexToBytes("534D4954483C3C4252454E44413C50")))),
			expDocDetails: DocumentDetails{OtherPersons: []mrz.MrzName{{Primary: "SMITH", Secondary: "BRENDA P"}}},
		},
		{
			// 5F1B: "SEE PAGE 51"
			name:          "5F1B EndorsementsAndObservations",
			tlvTag:        0x5F1B,
			tlvNode:       tlv.NewTlvConstructedNode(0x6C).AddChild(tlv.NewTlvSimpleNode(0x5F1B, utils.HexToBytes("5345452050414745203531"))),
			expDocDetails: DocumentDetails{EndorsementsAndObservations: "SEE PAGE 51"},
		},
		{
			// 5F1C: "NOT APPLICABLE"
			name:          "5F1C TaxExitRequirements",
			tlvTag:        0x5F1C,
			tlvNode:       tlv.NewTlvConstructedNode(0x6C).AddChild(tlv.NewTlvSimpleNode(0x5F1C, utils.HexToBytes("4E4F54204150504C494341424C45"))),
			expDocDetails: DocumentDetails{TaxExitRequirements: "NOT APPLICABLE"},
		},
		{
			// 5F1D: <image>
			name:          "5F1D ImageFront",
			tlvTag:        0x5F1D,
			tlvNode:       tlv.NewTlvConstructedNode(0x6C).AddChild(tlv.NewTlvSimpleNode(0x5F1D, utils.HexToBytes("ffd8ffe000104a46494600010100000100010000ffdb004300ffdb004301010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101ffc0000b080001000101011100ffc40014000100000000000000000000000000000000ffc40014100100000000000000000000000000000000ffda0008010100003f00d2cf20ffd9"))),
			expDocDetails: DocumentDetails{ImageFront: utils.HexToBytes("ffd8ffe000104a46494600010100000100010000ffdb004300ffdb004301010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101ffc0000b080001000101011100ffc40014000100000000000000000000000000000000ffc40014100100000000000000000000000000000000ffda0008010100003f00d2cf20ffd9")},
		},
		{
			// 5F1E: <image>
			name:          "5F1E ImageRear",
			tlvTag:        0x5F1E,
			tlvNode:       tlv.NewTlvConstructedNode(0x6C).AddChild(tlv.NewTlvSimpleNode(0x5F1E, utils.HexToBytes("ffd8ffe000104a46494600010100000100010000ffdb004300ffdb004301010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101ffc0000b080001000101011100ffc40014000100000000000000000000000000000000ffc40014100100000000000000000000000000000000ffda0008010100003f00d2cf20ffd9"))),
			expDocDetails: DocumentDetails{ImageRear: utils.HexToBytes("ffd8ffe000104a46494600010100000100010000ffdb004300ffdb004301010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101ffc0000b080001000101011100ffc40014000100000000000000000000000000000000ffc40014100100000000000000000000000000000000ffda0008010100003f00d2cf20ffd9")},
		},
		{
			// 5F26 (Date-of-issue): 4 bytes BCD 0x20210915
			name:          "5F26 DateOfIssue - BCD encoded (4 bytes)",
			tlvTag:        0x5F26,
			tlvNode:       tlv.NewTlvConstructedNode(0x6C).AddChild(tlv.NewTlvSimpleNode(0x5F26, utils.HexToBytes("20210915"))),
			expDocDetails: DocumentDetails{DateOfIssue: "20210915"},
		},
		{
			// 5F26 (Date-of-issue): 8 bytes ASCII 0x3230313730393035
			name:          "5F26 DateOfIssue - ASCII encoded (8 bytes)",
			tlvTag:        0x5F26,
			tlvNode:       tlv.NewTlvConstructedNode(0x6C).AddChild(tlv.NewTlvSimpleNode(0x5F26, utils.HexToBytes("3230313730393035"))),
			expDocDetails: DocumentDetails{DateOfIssue: "20170905"},
		},
		{
			// 5F55 (Perso-date-time): 7 bytes BCD 0x20171115013612
			name:          "5F55 PersoDateTime - BCD encoded (7 bytes)",
			tlvTag:        0x5F55,
			tlvNode:       tlv.NewTlvConstructedNode(0x6C).AddChild(tlv.NewTlvSimpleNode(0x5F55, utils.HexToBytes("20171115013612"))),
			expDocDetails: DocumentDetails{PersoDateTime: "20171115013612"},
		},
		{
			// 5F55 (Perso-date-time): 14 bytes ASCII 0x3230313730393035
			name:          "5F55 PersoDateTime - ASCII encoded (14 bytes)",
			tlvTag:        0x5F55,
			tlvNode:       tlv.NewTlvConstructedNode(0x6C).AddChild(tlv.NewTlvSimpleNode(0x5F55, utils.HexToBytes("3230313731313135303133363132"))),
			expDocDetails: DocumentDetails{PersoDateTime: "20171115013612"},
		},
		{
			// 5F56 (Perso-system-serial-number): "M-4060"
			name:          "5F56 PersoSystemSerialNumber",
			tlvTag:        0x5F56,
			tlvNode:       tlv.NewTlvConstructedNode(0x6C).AddChild(tlv.NewTlvSimpleNode(0x5F56, utils.HexToBytes("4d2d34303630"))),
			expDocDetails: DocumentDetails{PersoSystemSerialNumber: "M-4060"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var docDetails DocumentDetails

			err := docDetails.processTag(tc.tlvTag, tc.tlvNode)
			if err != nil {
				t.Errorf("Unexpected processTag error: %s", err)
			}

			// verify data
			if !reflect.DeepEqual(tc.expDocDetails, docDetails) {
				t.Errorf("DocumentDetails differs to expected [Exp] %+v [Act] %+v", tc.expDocDetails, docDetails)
			}
		})
	}
}

func TestProcessTagErrors(t *testing.T) {
	testCases := []struct {
		name          string
		tlvTag        tlv.TlvTag
		tlvNode       tlv.TlvNode
		errorContains string
	}{
		{
			// 5F1A: OtherPersons: [1] SMITH, BRENDA P -> SMITH, BRENDA, P
			name:          "5F1A OtherPersons",
			tlvTag:        0x5F1A,
			tlvNode:       tlv.NewTlvConstructedNode(0x6C).AddChild(tlv.NewTlvConstructedNode(0xA0).AddChild(tlv.NewTlvSimpleNode(0x02, []byte{0x01})).AddChild(tlv.NewTlvSimpleNode(0x5F1A, utils.HexToBytes("534D4954483C3C4252454E44413C3C50")))),
			errorContains: "[ParseName] Incorrect number of name components: 3",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var docDetails DocumentDetails

			err := docDetails.processTag(tc.tlvTag, tc.tlvNode)
			if err == nil {
				t.Errorf("Expected error")
			}

			if !bytes.Contains([]byte(err.Error()), []byte(tc.errorContains)) {
				t.Errorf("Expected error to contain '%s', got: %s", tc.errorContains, err.Error())
			}
		})
	}
}
