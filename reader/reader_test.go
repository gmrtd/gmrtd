package reader

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/utils"
)

type MockStatus struct{}

func (s *MockStatus) Status(_ string) {
	// NB do nothing
}

func TestReaderSetup(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.MockTransceiver{})
	var reader *Reader = NewReader(&status, nfc)

	if reader.skipPace {
		t.Errorf("Reader should default to PACE=Yes")
	}

	reader.SkipPace()

	if !reader.skipPace {
		t.Errorf("Reader should now have PACE=NO")
	}
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
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{utils.HexToBytes("6A82")}) // 6A82: file not found
	var reader *Reader = NewReader(&status, nfc)
	var doc document.Document

	// NB expect error as SOD is not present ans this is a critical file
	//	  - especially as it drives the reading of the DGs
	err := reader.readLDS1files(&doc)

	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestReadEfSod(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{utils.HexToBytes("6A82")}) // 6A82: file not found
	var reader *Reader = NewReader(&status, nfc)
	var doc document.Document

	err := reader.readEfSod(&doc)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
}

func TestReadEfCom(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{utils.HexToBytes("6A82")}) // 6A82: file not found
	var reader *Reader = NewReader(&status, nfc)
	var doc document.Document

	err := reader.readEfCom(&doc)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
}

type PanicTransceiver struct {
	P any
}

func (t *PanicTransceiver) Transceive(cla, ins, p1, p2 int, data []byte, le int, rapdu []byte) []byte {
	panic(t.P)
}

func TestReadDocumentTransceiverPanicIsHandled(t *testing.T) {
	cases := []struct {
		name  string
		panic any
	}{
		{"panic:string", "Transceiver that always panics"},
		{"panic:error", fmt.Errorf("Transceiver that always panics")},
		{"panic:other", []byte{1, 2, 3, 4, 5}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var status MockStatus
			var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&PanicTransceiver{P: tc.panic})
			reader := NewReader(&status, nfc)
			pass := password.NewPasswordCan("123456")

			_, err := reader.ReadDocument(pass, nil, nil)
			if err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}
