package document

import (
	"reflect"
	"testing"

	"github.com/gmrtd/gmrtd/mrz"
	"github.com/gmrtd/gmrtd/utils"
)

func TestNewDG16NoData(t *testing.T) {
	if dg16, err := NewDG16(nil); dg16 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if dg16, err := NewDG16([]byte{}); dg16 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewDG16UnhappyRootTag(t *testing.T) {
	var dg16bytes []byte = utils.HexToBytes("01021234") // valid TLV but invalid DG16, as tag 70 is missing

	dg16, err := NewDG16(dg16bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg16 != nil {
		t.Errorf("DG16 not expected for error case")
	}
}

func TestNewDG16Happy(t *testing.T) {
	// (9303p10) A.6 EF.DG16 PERSON(S) TO NOTIFY
	//
	// ‘70’ ‘81A2’
	// 		‘02’ ‘01’ 2
	// 		‘A1’ ‘4C’
	// 			‘5F50’ ‘08’ 20020101								5F50083230303230313031
	// 			‘5F51’ ‘10’ SMITH<<CHARLES<R						5F5110534D4954483C3C434841524C45533C52
	// 			‘5F52’ ‘0B’ 19525551212								5F520B3139353235353531323132
	// 			‘5F53’ ‘1D’ 123 MAPLE RD<ANYTOWN<MN<55100			5F531D313233204D41504C452052443C414E59544F574E3C4D4E3C3535313030
	// 		‘A2’ ‘4F’
	// 			‘5F50’ ‘08’ 20020315								5F50083230303230333135
	// 			‘5F51’ ‘0D’ BROWN<<MARY<J							5F510D42524F574E3C3C4D4152593C4A
	// 			‘5F52’ ‘0B’ 14155551212								5F520B3134313535353531323132
	// 			‘5F53’ ‘23’ 49 REDWOOD LN<OCEAN BREEZE<CA<94000		5F5323343920524544574F4F44204C4E3C4F4345414E20425245455A453C43413C3934303030
	//
	// --> 7081A2020102A14C5F500832303032303130315F5110534D4954483C3C434841524C45533C525F520B31393532353535313231325F531D313233204D41504C452052443C414E59544F574E3C4D4E3C3535313030A24F5F500832303032303331355F510D42524F574E3C3C4D4152593C4A5F520B31343135353535313231325F5323343920524544574F4F44204C4E3C4F4345414E20425245455A453C43413C3934303030

	testCases := []struct {
		dg16bytes  []byte
		expPersons []PersonToNotify
	}{
		{
			dg16bytes:  utils.HexToBytes("7081A2020102A14C5F500832303032303130315F5110534D4954483C3C434841524C45533C525F520B31393532353535313231325F531D313233204D41504C452052443C414E59544F574E3C4D4E3C3535313030A24F5F500832303032303331355F510D42524F574E3C3C4D4152593C4A5F520B31343135353535313231325F5323343920524544574F4F44204C4E3C4F4345414E20425245455A453C43413C3934303030"),
			expPersons: []PersonToNotify{PersonToNotify{DateRecorded: "20020101", Name: mrz.MrzName{Primary: "SMITH", Secondary: "CHARLES R"}, Telephone: "19525551212", Address: []string{"123 MAPLE RD", "ANYTOWN", "MN", "55100"}}, PersonToNotify{DateRecorded: "20020315", Name: mrz.MrzName{Primary: "BROWN", Secondary: "MARY J"}, Telephone: "14155551212", Address: []string{"49 REDWOOD LN", "OCEAN BREEZE", "CA", "94000"}}},
		},
	}
	for _, tc := range testCases {
		var doc Document

		err := doc.NewDG(16, tc.dg16bytes)

		if err != nil {
			t.Errorf("Error not expected")
		}

		if doc.Mf.Lds1.Dg16 == nil {
			t.Errorf("DG16 expected")
			break
		}

		if !reflect.DeepEqual(doc.Mf.Lds1.Dg16.PersonsToNotify, tc.expPersons) {
			t.Errorf("DG16 PersonsToNotify differs to expected\n(Act:%+v)\n(Exp:%+v)", doc.Mf.Lds1.Dg16.PersonsToNotify, tc.expPersons)
		}
	}
}
