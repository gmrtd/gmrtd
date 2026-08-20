package reader

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/utils"
)

func TestStatusPhaseString(t *testing.T) {
	phases := []StatusPhase{
		STATUS_PHASE_CONNECTING,
		STATUS_PHASE_READING_CARD_ACCESS,
		STATUS_PHASE_ACCESS_CONTROL_PACE,
		STATUS_PHASE_ACCESS_CONTROL_BAC,
		STATUS_PHASE_READING_DIR,
		STATUS_PHASE_READING_SECURITY_OBJECT,
		STATUS_PHASE_READING_COMMON_DATA,
		STATUS_PHASE_READING_DATA_GROUP,
		STATUS_PHASE_ACTIVE_AUTHENTICATION,
		STATUS_PHASE_CHIP_AUTHENTICATION,
		STATUS_PHASE_VERIFYING_DOCUMENT,
		STATUS_PHASE_PASSIVE_AUTHENTICATION,
		STATUS_PHASE_FINISHED,
	}

	for _, phase := range phases {
		if strings.Contains(phase.String(), "*UnsupportedValue*") {
			t.Errorf("phase %d has no description", int(phase))
		}
	}

	// a value outside the set should be reported as such, not silently described
	if !strings.Contains(StatusPhase(99).String(), "*UnsupportedValue*") {
		t.Errorf("expected *UnsupportedValue* for phase 99 (act:%s)", StatusPhase(99).String())
	}
}

func TestStatusString(t *testing.T) {
	tests := []struct {
		name   string
		status Status
		exp    string
	}{
		{"data-group", Status{Phase: STATUS_PHASE_READING_DATA_GROUP, DataGroup: 1}, "Reading DG01"},
		{"data-group (2 digits)", Status{Phase: STATUS_PHASE_READING_DATA_GROUP, DataGroup: 14}, "Reading DG14"},
		{"other phase", Status{Phase: STATUS_PHASE_READING_COMMON_DATA}, "Reading EF.COM"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if act := tc.status.String(); act != tc.exp {
				t.Errorf("Status.String differs to expected (act:%s) (exp:%s)", act, tc.exp)
			}
		})
	}
}

// verifies that each read step reports its own phase, and that no phase carries a
// data-group number other than the data-group read itself
func TestStepsReportPhase(t *testing.T) {
	tests := []struct {
		name string
		step ReaderStep
		exp  StatusPhase
	}{
		{"selectMF", selectMF, STATUS_PHASE_CONNECTING},
		{"readEfCardAccess", readEfCardAccess, STATUS_PHASE_READING_CARD_ACCESS},
		{"readEfDir", readEfDir, STATUS_PHASE_READING_DIR},
		{"readEfSod", readEfSod, STATUS_PHASE_READING_SECURITY_OBJECT},
		{"readEfCom", readEfCom, STATUS_PHASE_READING_COMMON_DATA},
		{"performChipAuthentication", performChipAuthentication, STATUS_PHASE_ACTIVE_AUTHENTICATION},
		{"verifyDocument", verifyDocument, STATUS_PHASE_VERIFYING_DOCUMENT},
		{"performPassiveAuthentication", performPassiveAuthentication, STATUS_PHASE_PASSIVE_AUTHENTICATION},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var status MockStatus
			// 6A82: file not found - every step above completes (or soft-fails) on it
			var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6A82")})
			var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
			var state *ReaderState = NewReaderState(nil, nil, password.NewPasswordNil())

			_ = tc.step(reader, state)

			recorded := status.Recorded()
			if len(recorded) < 1 {
				t.Fatalf("expected a status update")
			}

			if recorded[0].Phase != tc.exp {
				t.Errorf("first phase differs to expected (act:%d) (exp:%d)", int(recorded[0].Phase), int(tc.exp))
			}

			if recorded[0].DataGroup != 0 {
				t.Errorf("expected no data-group for phase %d (act:%d)", int(tc.exp), recorded[0].DataGroup)
			}
		})
	}
}

// verifies that PACE and BAC report the access-control phase they perform
func TestAccessControlStepsReportPhase(t *testing.T) {
	var err error

	// valid CardAccess from SG passport, indicating PACE is supported
	var cardAccess *document.CardAccess
	cardAccess, err = document.NewCardAccess(utils.HexToBytes("31143012060A04007F0007020204020402010202010D"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	tests := []struct {
		name string
		step ReaderStep
		exp  StatusPhase
	}{
		{"performPace", performPace, STATUS_PHASE_ACCESS_CONTROL_PACE},
		{"performBac", performBac, STATUS_PHASE_ACCESS_CONTROL_BAC},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var pass *password.Password
			pass, err = password.NewPasswordMrzi("123456", "100101", "301225")
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			var status MockStatus
			// 6FFF: card dead - the protocol fails, but the phase is reported before it starts
			var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6FFF")})
			var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
			var state *ReaderState = NewReaderState(nil, nil, pass)

			state.docEx.Document.Mf.CardAccess = cardAccess

			err = tc.step(reader, state)
			if tc.name == "performPace" {
				// Default is fail-closed on PACE error; phase is still reported first.
				if err == nil {
					t.Fatalf("expected PACE error (fail-closed default)")
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			exp := []Status{{Phase: tc.exp}}
			if act := status.Recorded(); !reflect.DeepEqual(act, exp) {
				t.Errorf("recorded statuses differ to expected (act:%v) (exp:%v)", act, exp)
			}
		})
	}
}

// verifies that a data-group read identifies WHICH data-group is being read,
// which is what the free-text status could only express as English prose
func TestReadLDS1DgsReportsDataGroup(t *testing.T) {
	var status MockStatus
	// 6A82: file not found - the data-groups are reported, then skipped
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6A82")})
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var state *ReaderState = NewReaderState(nil, nil, password.NewPasswordNil())

	state.docEx.Document.Mf.Lds1.Sod = &document.SOD{
		LdsSecurityObject: &document.LDSSecurityObject{
			DataGroupHashValues: []document.DataGroupHash{
				{DataGroupNumber: 1},
				{DataGroupNumber: 2},
				{DataGroupNumber: 3}, // no file-id, so never read and never reported
				{DataGroupNumber: 14},
			},
		},
	}

	if err := readLDS1dgs(reader, state); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	exp := []Status{
		{Phase: STATUS_PHASE_READING_DATA_GROUP, DataGroup: 1},
		{Phase: STATUS_PHASE_READING_DATA_GROUP, DataGroup: 2},
		{Phase: STATUS_PHASE_READING_DATA_GROUP, DataGroup: 14},
	}

	if act := status.Recorded(); !reflect.DeepEqual(act, exp) {
		t.Errorf("recorded statuses differ to expected (act:%v) (exp:%v)", act, exp)
	}
}

func TestReadLDS1DgsSkipImagesReportsNoDataGroup(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&PanicTransceiver{P: "no file reads expected when skipImages is set"})
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var state *ReaderState = NewReaderState(nil, nil, password.NewPasswordNil())

	state.docEx.Document.Mf.Lds1.Sod = &document.SOD{
		LdsSecurityObject: &document.LDSSecurityObject{
			DataGroupHashValues: []document.DataGroupHash{
				{DataGroupNumber: 2},
				{DataGroupNumber: 7},
			},
		},
	}

	reader.SkipImages()

	if err := readLDS1dgs(reader, state); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if act := status.Recorded(); len(act) != 0 {
		t.Errorf("expected no status updates for skipped data-groups (act:%v)", act)
	}
}

// singleFileTransceiver serves one EF from memory: SELECT succeeds for the MF, the
// MRTD AID and that one file-id, READ BINARY returns slices of its contents, and
// every other file is reported as not found. Enough for a read to run all of its
// steps without a card.
type singleFileTransceiver struct {
	fileId   uint16
	fileData []byte
	selected bool
}

var _ iso7816.Transceiver = (*singleFileTransceiver)(nil)

func (transceiver *singleFileTransceiver) Transceive(_ int, ins int, p1 int, p2 int, data []byte, le int, _ []byte) []byte {
	const rApduSuccess = "9000"
	const rApduFileNotFound = "6A82"
	const rApduNotSupported = "6D00"

	switch {
	case ins == int(iso7816.INS_SELECT) && p1 == 0x02: // select EF
		transceiver.selected = bytes.Equal(data, utils.UInt16ToBytes(transceiver.fileId))
		if !transceiver.selected {
			return utils.HexToBytes(rApduFileNotFound)
		}
		return utils.HexToBytes(rApduSuccess)

	case ins == int(iso7816.INS_SELECT): // select MF / AID
		return utils.HexToBytes(rApduSuccess)

	case ins == int(iso7816.INS_READ_BINARY):
		if !transceiver.selected {
			return utils.HexToBytes(rApduFileNotFound)
		}

		offset := (p1 * 256) + p2
		if offset > len(transceiver.fileData) {
			return utils.HexToBytes(rApduFileNotFound)
		}

		end := min(offset+le, len(transceiver.fileData))

		return append(transceiver.fileData[offset:end:end], utils.HexToBytes(rApduSuccess)...)
	}

	// anything else (e.g. the BAC/PACE commands) is reported as unsupported
	return utils.HexToBytes(rApduNotSupported)
}

// verifies the phases a complete read reports, in order, including the data-group
// numbers and the final completion phase
func TestReadDocumentReportsPhases(t *testing.T) {
	// the sample document's SOD carries hashes for DG1, DG2, DG3, DG11, DG12 and
	// DG14 - DG3 has no file-id, so it is never read and never reported
	sampleDoc, err := document.SampleDocument()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	var status MockStatus
	transceiver := &singleFileTransceiver{fileId: MRTDFileIdEFSOD, fileData: sampleDoc.Mf.Lds1.Sod.RawData}
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(transceiver)
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))

	pass, err := password.NewPasswordMrzi("123456", "100101", "301225")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if _, _, err = reader.ReadDocument(pass, nil, nil); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	exp := []Status{
		{Phase: STATUS_PHASE_CONNECTING},
		{Phase: STATUS_PHASE_READING_CARD_ACCESS},
		{Phase: STATUS_PHASE_ACCESS_CONTROL_PACE},
		{Phase: STATUS_PHASE_ACCESS_CONTROL_BAC},
		{Phase: STATUS_PHASE_READING_DIR},
		{Phase: STATUS_PHASE_READING_SECURITY_OBJECT},
		{Phase: STATUS_PHASE_READING_COMMON_DATA},
		{Phase: STATUS_PHASE_READING_DATA_GROUP, DataGroup: 1},
		{Phase: STATUS_PHASE_READING_DATA_GROUP, DataGroup: 2},
		{Phase: STATUS_PHASE_READING_DATA_GROUP, DataGroup: 11},
		{Phase: STATUS_PHASE_READING_DATA_GROUP, DataGroup: 12},
		{Phase: STATUS_PHASE_READING_DATA_GROUP, DataGroup: 14},
		{Phase: STATUS_PHASE_ACTIVE_AUTHENTICATION},
		{Phase: STATUS_PHASE_CHIP_AUTHENTICATION},
		{Phase: STATUS_PHASE_VERIFYING_DOCUMENT},
		{Phase: STATUS_PHASE_PASSIVE_AUTHENTICATION},
		{Phase: STATUS_PHASE_FINISHED},
	}

	if act := status.Recorded(); !reflect.DeepEqual(act, exp) {
		t.Errorf("recorded statuses differ to expected (act:%v) (exp:%v)", act, exp)
	}
}

// a read that fails does not report completion
func TestReadDocumentFailureReportsNoFinishedPhase(t *testing.T) {
	var status MockStatus
	// 6FFF: card dead. SelectMF now tolerates any error (it's not essential to the read), so
	// the read proceeds past STATUS_PHASE_CONNECTING and actually fails on the next exchange,
	// reading EF.CardAccess.
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6FFF")})
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))

	if _, _, err := reader.ReadDocument(password.NewPasswordNil(), nil, nil); err == nil {
		t.Fatalf("expected error")
	}

	exp := []Status{{Phase: STATUS_PHASE_CONNECTING}, {Phase: STATUS_PHASE_READING_CARD_ACCESS}}
	if act := status.Recorded(); !reflect.DeepEqual(act, exp) {
		t.Errorf("recorded statuses differ to expected (act:%v) (exp:%v)", act, exp)
	}
}

// a nil ReaderStatus must not panic: the first phase is now reported by the very
// first read step, so a caller that passes nil would otherwise lose the real error
func TestReadDocumentNilStatusReportsRealError(t *testing.T) {
	// 6FFF: card dead. SelectMF tolerates this and the read proceeds to reading
	// EF.CardAccess, which is where it actually fails.
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6FFF")})
	var reader *Reader = NewReader(nil, nfc, EmptyCscaTrustStore(t))

	_, _, err := reader.ReadDocument(password.NewPasswordNil(), nil, nil)
	if err == nil {
		t.Fatalf("expected error")
	}

	if strings.Contains(err.Error(), "nil pointer") {
		t.Errorf("nil ReaderStatus masked the read error (act:%s)", err)
	}

	if !strings.Contains(err.Error(), "readEfCardAccess") {
		t.Errorf("expected the readEfCardAccess failure to be reported (act:%s)", err)
	}
}
