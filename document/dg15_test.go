package document

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestNewDG15NoData(t *testing.T) {
	if dg15, err := NewDG15(nil); dg15 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if dg15, err := NewDG15([]byte{}); dg15 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewDG15BadTlv(t *testing.T) {
	var dg15bytes []byte = utils.HexToBytes("02101234") // invalid TLV encoding - insufficient bytes

	dg15, err := NewDG15(dg15bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg15 != nil {
		t.Errorf("DG not expected for error case")
	}
}

func TestNewDG15UnhappyRootTag(t *testing.T) {
	var dg15bytes []byte = utils.HexToBytes("01021234") // valid TLV but invalid DG15, as tag 6F is missing

	dg15, err := NewDG15(dg15bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg15 != nil {
		t.Errorf("DG15 not expected for error case")
	}
}

func TestNewDG15MissingKeyErr(t *testing.T) {
	var dg15bytes []byte = utils.HexToBytes("6F00") // valid file header, but missing key (x30)

	dg15, err := NewDG15(dg15bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg15 != nil {
		t.Errorf("DG15 not expected for error case")
	}
}

func TestNewDG15(t *testing.T) {
	var dg15bytes []byte = utils.HexToBytes("6F8201023081FF300D06092A864886F70D01010105000381ED003081E90281E100BB8F93F4DC95E205CDA17C6927AB1E365B13065D03CD12E0FCE95D96840529453202F56CC4C13F77CD062930C8BC89A2873B257045C286E601CF3C09323A53103314902804AA10A314628CE222206A8866946A36B442041BB54AC81E6855DD1D6E16101833D65A191C20AC8B33B8A1A32920F46043F8031CF2BC17417030865FC5BE5A39DEE423BCBA3CA8177168EB23CFE01BA43EC87711B1CFFF85DB46F300DD8AE317B50D543B573E119E23AF7070D0B2FED6A3B2313A5EC02A531AAED1741F4390D1013E2A0F081EAC5DC8B0A1B2C6BDB1206F08D30E3643E1E5BDF536110203010001")

	var doc Document

	err := doc.NewDG(15, dg15bytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	var dg15 *DG15 = doc.Mf.Lds1.Dg15

	var expPubKeyBytes []byte = utils.HexToBytes("3081FF300D06092A864886F70D01010105000381ED003081E90281E100BB8F93F4DC95E205CDA17C6927AB1E365B13065D03CD12E0FCE95D96840529453202F56CC4C13F77CD062930C8BC89A2873B257045C286E601CF3C09323A53103314902804AA10A314628CE222206A8866946A36B442041BB54AC81E6855DD1D6E16101833D65A191C20AC8B33B8A1A32920F46043F8031CF2BC17417030865FC5BE5A39DEE423BCBA3CA8177168EB23CFE01BA43EC87711B1CFFF85DB46F300DD8AE317B50D543B573E119E23AF7070D0B2FED6A3B2313A5EC02A531AAED1741F4390D1013E2A0F081EAC5DC8B0A1B2C6BDB1206F08D30E3643E1E5BDF536110203010001")

	if !bytes.Equal(dg15.SubjectPublicKeyInfoBytes, expPubKeyBytes) {
		t.Errorf("Data differs to expected (exp:%x, act:%x)", expPubKeyBytes, dg15.SubjectPublicKeyInfoBytes)
	}

}
