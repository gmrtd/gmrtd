package document

import (
	"bytes"
	"testing"
)

func TestGetRawDataCardAccess(t *testing.T) {
	want := []byte{0x01, 0x02, 0x03}
	f := &CardAccess{RawData: want}
	if got := f.GetRawData(); !bytes.Equal(got, want) {
		t.Errorf("CardAccess.GetRawData() = %x, want %x", got, want)
	}
}

func TestGetRawDataCardSecurity(t *testing.T) {
	want := []byte{0x04, 0x05, 0x06}
	f := &CardSecurity{RawData: want}
	if got := f.GetRawData(); !bytes.Equal(got, want) {
		t.Errorf("CardSecurity.GetRawData() = %x, want %x", got, want)
	}
}

func TestGetRawDataEFDIR(t *testing.T) {
	want := []byte{0x07, 0x08, 0x09}
	f := &EFDIR{RawData: want}
	if got := f.GetRawData(); !bytes.Equal(got, want) {
		t.Errorf("EFDIR.GetRawData() = %x, want %x", got, want)
	}
}

func TestGetRawDataCOM(t *testing.T) {
	want := []byte{0x0a, 0x0b, 0x0c}
	f := &COM{RawData: want}
	if got := f.GetRawData(); !bytes.Equal(got, want) {
		t.Errorf("COM.GetRawData() = %x, want %x", got, want)
	}
}

func TestGetRawDataSOD(t *testing.T) {
	want := []byte{0x0d, 0x0e, 0x0f}
	f := &SOD{RawData: want}
	if got := f.GetRawData(); !bytes.Equal(got, want) {
		t.Errorf("SOD.GetRawData() = %x, want %x", got, want)
	}
}

func TestGetRawDataDG1(t *testing.T) {
	want := []byte{0x10, 0x11, 0x12}
	f := &DG1{RawData: want}
	if got := f.GetRawData(); !bytes.Equal(got, want) {
		t.Errorf("DG1.GetRawData() = %x, want %x", got, want)
	}
}

func TestGetRawDataDG2(t *testing.T) {
	want := []byte{0x13, 0x14, 0x15}
	f := &DG2{RawData: want}
	if got := f.GetRawData(); !bytes.Equal(got, want) {
		t.Errorf("DG2.GetRawData() = %x, want %x", got, want)
	}
}

func TestGetRawDataDG7(t *testing.T) {
	want := []byte{0x16, 0x17, 0x18}
	f := &DG7{RawData: want}
	if got := f.GetRawData(); !bytes.Equal(got, want) {
		t.Errorf("DG7.GetRawData() = %x, want %x", got, want)
	}
}

func TestGetRawDataDG11(t *testing.T) {
	want := []byte{0x19, 0x1a, 0x1b}
	f := &DG11{RawData: want}
	if got := f.GetRawData(); !bytes.Equal(got, want) {
		t.Errorf("DG11.GetRawData() = %x, want %x", got, want)
	}
}

func TestGetRawDataDG12(t *testing.T) {
	want := []byte{0x1c, 0x1d, 0x1e}
	f := &DG12{RawData: want}
	if got := f.GetRawData(); !bytes.Equal(got, want) {
		t.Errorf("DG12.GetRawData() = %x, want %x", got, want)
	}
}

func TestGetRawDataDG13(t *testing.T) {
	want := []byte{0x1f, 0x20, 0x21}
	f := &DG13{RawData: want}
	if got := f.GetRawData(); !bytes.Equal(got, want) {
		t.Errorf("DG13.GetRawData() = %x, want %x", got, want)
	}
}

func TestGetRawDataDG14(t *testing.T) {
	want := []byte{0x22, 0x23, 0x24}
	f := &DG14{RawData: want}
	if got := f.GetRawData(); !bytes.Equal(got, want) {
		t.Errorf("DG14.GetRawData() = %x, want %x", got, want)
	}
}

func TestGetRawDataDG15(t *testing.T) {
	want := []byte{0x25, 0x26, 0x27}
	f := &DG15{RawData: want}
	if got := f.GetRawData(); !bytes.Equal(got, want) {
		t.Errorf("DG15.GetRawData() = %x, want %x", got, want)
	}
}

func TestGetRawDataDG16(t *testing.T) {
	want := []byte{0x28, 0x29, 0x2a}
	f := &DG16{RawData: want}
	if got := f.GetRawData(); !bytes.Equal(got, want) {
		t.Errorf("DG16.GetRawData() = %x, want %x", got, want)
	}
}
