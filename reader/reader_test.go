package reader

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/utils"
)

type MockStatus struct{}

func (s *MockStatus) Status(_ string) {
	// NB do nothing
}

func TestReaderSetup(t *testing.T) {
	var status MockStatus
	var reader *Reader = NewReader(&status)

	if reader.skipPace {
		t.Errorf("Reader should default to PACE=Yes")
	}

	reader.SkipPace()

	if !reader.skipPace {
		t.Errorf("Reader should now have PACE=NO")
	}

	reader.SetApduMaxLe(65536)

	if reader.apduMaxLe != 65536 {
		t.Errorf("APDU Max Le should be 65536")
	}
}

func TestReaderSetApduMaxLeTooSmallError(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	var status MockStatus
	var reader *Reader = NewReader(&status)

	reader.SetApduMaxLe(-1) // min valid: 0

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestReaderSetApduMaxLeTooBigError(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	var status MockStatus
	var reader *Reader = NewReader(&status)

	reader.SetApduMaxLe(65537) // max valid: 65535

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestRecordAtrAts(t *testing.T) {
	var expAtr []byte = utils.HexToBytes("1234567890")
	var expAts []byte = utils.HexToBytes("ABCDEF")

	var session document.Session

	recordAtrAts(expAtr, expAts, &session)

	// verify that ATR was recorded
	if !bytes.Equal(session.ChipActivationRsp.Atr, expAtr) {
		t.Errorf("ATR differs to expected (act:%X) (exp:%X)", session.ChipActivationRsp.Atr, expAtr)
	}

	// verify that ATS was recorded
	if !bytes.Equal(session.ChipActivationRsp.Ats, expAts) {
		t.Errorf("ATS differs to expected (act:%X) (exp:%X)", session.ChipActivationRsp.Ats, expAts)
	}
}

func TestReadLDS1filesMissingSodError(t *testing.T) {
	var status MockStatus
	var reader *Reader = NewReader(&status)
	var doc document.Document

	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{utils.HexToBytes("6A82")}) // 6A82: file not found

	// NB expect error as SOD is not present ans this is a critical file
	//	  - especially as it drives the reading of the DGs
	err := reader.readLDS1files(nfc, &doc)

	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestReadEfSod(t *testing.T) {
	var status MockStatus
	var reader *Reader = NewReader(&status)
	var doc document.Document

	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{utils.HexToBytes("6A82")}) // 6A82: file not found

	err := reader.readEfSod(nfc, &doc)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
}

func TestReadEfCom(t *testing.T) {
	var status MockStatus
	var reader *Reader = NewReader(&status)
	var doc document.Document

	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{utils.HexToBytes("6A82")}) // 6A82: file not found

	err := reader.readEfCom(nfc, &doc)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
}
