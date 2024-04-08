package gmrtd

import (
	"testing"
)

func TestNewEFDIRNoData(t *testing.T) {
	if NewEFDIR(nil) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
	if NewEFDIR([]byte{}) != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

// TODO - add test case from 9303p10.. Table 31. EF.DIR Format
//			low priority as EF.DIR only required if multiple apps present
