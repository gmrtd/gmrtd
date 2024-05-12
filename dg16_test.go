package gmrtd

import (
	"testing"
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
	var dg16bytes []byte = HexToBytes("01021234") // valid TLV but invalid DG16, as tag 70 is missing

	dg16, err := NewDG16(dg16bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg16 != nil {
		t.Errorf("DG16 not expected for error case")
	}
}

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
// 			‘5F50’ ‘08’ 20020315								5F503230303230333135
// 			‘5F51’ ‘0D’ BROWN<<MARY<J							5F510D42524F574E3C3C4D4152593C4A
// 			‘5F52’ ‘0B’ 14155551212								5F520B3134313535353531323132
// 			‘5F53’ ‘23’ 49 REDWOOD LN<OCEAN BREEZE<CA<94000		5F5323343920524544574F4F44204C4E3C4F4345414E20425245455A453C43413C3934303030

// TODO - add test case
