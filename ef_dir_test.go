package gmrtd

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestNewEFDIRNoData(t *testing.T) {
	if NewEFDIR(nil) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
	if NewEFDIR([]byte{}) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewEFDIR(t *testing.T) {
	// Table 31. (EF.DIR Format) - 9303 p10
	fileBytes := utils.HexToBytes("61094F07A000000247100161094F07A000000247200161094F07A000000247200261094F07A0000002472003")

	var efDir *EFDIR = NewEFDIR(fileBytes)

	if len(efDir.Application) != 4 {
		t.Errorf("4 entries expected")
	}

	if !bytes.Equal(efDir.Application[0].aid, utils.HexToBytes("A0000002471001")) {
		t.Errorf("Incorrect application #1")
	}

	if !bytes.Equal(efDir.Application[1].aid, utils.HexToBytes("A0000002472001")) {
		t.Errorf("Incorrect application #2")
	}

	if !bytes.Equal(efDir.Application[2].aid, utils.HexToBytes("A0000002472002")) {
		t.Errorf("Incorrect application #3")
	}

	if !bytes.Equal(efDir.Application[3].aid, utils.HexToBytes("A0000002472003")) {
		t.Errorf("Incorrect application #4")
	}
}
