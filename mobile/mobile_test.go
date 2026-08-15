package mobile

import (
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/reader"
)

func TestNewPasswordMrz(t *testing.T) {
	pass, err := NewPasswordMrz("I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<8")
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	if pass.password.Password != "D23145890734934071279507122" {
		t.Fatalf("password mismatch")
	}
}

func TestNewPasswordMrzError(t *testing.T) {
	// NB invalid MRZ length (added 'A' to end)
	_, err := NewPasswordMrz("I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<8A")
	if err == nil {
		t.Fatalf("Expected error")
	}
}

func TestNewPasswordMrzi(t *testing.T) {
	pass, err := NewPasswordMrzi("D23145890734", "340712", "950712")
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	if pass.password.Password != "D23145890734934071279507122" {
		t.Fatalf("password mismatch")
	}
}

func TestNewPasswordMrziError(t *testing.T) {
	// NB invalid characters in DocumentNo (i.e. lower-case)
	_, err := NewPasswordMrzi("d23145890734", "340712", "950712")
	if err == nil {
		t.Fatalf("Expected error")
	}
}

func TestNewPasswordCan(t *testing.T) {
	_, err := NewPasswordCan("123456")
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
}

func TestSetApduMaxLe(t *testing.T) {
	tests := []struct {
		name        string
		maxRead     int
		wantErr     bool
		wantMaxRead int
	}{
		{
			name:        "zero disables override",
			maxRead:     0,
			wantErr:     false,
			wantMaxRead: 0,
		},
		{
			name:        "minimum valid value",
			maxRead:     1,
			wantErr:     false,
			wantMaxRead: 1,
		},
		{
			name:        "typical valid value",
			maxRead:     1000,
			wantErr:     false,
			wantMaxRead: 1000,
		},
		{
			name:        "maximum valid value",
			maxRead:     65536,
			wantErr:     false,
			wantMaxRead: 65536,
		},
		{
			name:        "negative value rejected",
			maxRead:     -1,
			wantErr:     true,
			wantMaxRead: 0,
		},
		{
			name:        "above maximum rejected",
			maxRead:     65537,
			wantErr:     true,
			wantMaxRead: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &Reader{}

			err := reader.SetApduMaxLe(tt.maxRead)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}

				if reader.maxRead != tt.wantMaxRead {
					t.Fatalf("maxRead changed on error: got %d, want %d", reader.maxRead, tt.wantMaxRead)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			if reader.maxRead != tt.wantMaxRead {
				t.Fatalf("maxRead mismatch: got %d, want %d", reader.maxRead, tt.wantMaxRead)
			}
		})
	}
}

func TestSkipPace(t *testing.T) {
	reader := &Reader{}

	if reader.skipPace {
		t.Fatalf("skipPace should default to false")
	}

	reader.SkipPace()

	if !reader.skipPace {
		t.Fatalf("skipPace should be true after calling SkipPace()")
	}
}

func TestSkipImages(t *testing.T) {
	reader := &Reader{}

	if reader.skipImages {
		t.Fatalf("skipImages should default to false")
	}

	reader.SkipImages()

	if !reader.skipImages {
		t.Fatalf("skipImages should be true after calling SkipImages()")
	}
}

func TestWithAAChallenge(t *testing.T) {
	t.Run("valid 8 bytes", func(t *testing.T) {
		r, err := (&Reader{}).WithAAChallenge(make([]byte, 8))
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if r == nil {
			t.Errorf("expected non-nil reader")
		}
	})

	invalidSizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"7 bytes", 7},
		{"9 bytes", 9},
		{"16 bytes", 16},
	}
	for _, tc := range invalidSizes {
		t.Run(tc.name, func(t *testing.T) {
			_, err := (&Reader{}).WithAAChallenge(make([]byte, tc.size))
			if err == nil {
				t.Errorf("expected error for challenge of length %d", tc.size)
			}
		})
	}
}

// testReaderStatus records the status updates a host application would receive
// through the binding.
// NB guarded by a mutex because TestReaderConcurrentAccess shares one instance.
type testReaderStatus struct {
	mu       sync.Mutex
	statuses [][2]int
}

func (status *testReaderStatus) Status(phase, dataGroup int) {
	status.mu.Lock()
	defer status.mu.Unlock()
	status.statuses = append(status.statuses, [2]int{phase, dataGroup})
}

func (status *testReaderStatus) Recorded() [][2]int {
	status.mu.Lock()
	defer status.mu.Unlock()
	return append([][2]int(nil), status.statuses...)
}

// the phase values are part of the binding's contract: a host application built
// against an earlier release compares the ints it receives against these, so they
// must not be renumbered
func TestStatusPhaseValues(t *testing.T) {
	exp := map[string]int{
		"connecting":              1,
		"reading card access":     2,
		"access control (PACE)":   3,
		"access control (BAC)":    4,
		"reading EF.DIR":          5,
		"reading security object": 6,
		"reading common data":     7,
		"reading data group":      8,
		"active authentication":   9,
		"chip authentication":     10,
		"verifying document":      11,
		"passive authentication":  12,
		"finished":                13,
	}

	act := map[string]int{
		"connecting":              STATUS_PHASE_CONNECTING,
		"reading card access":     STATUS_PHASE_READING_CARD_ACCESS,
		"access control (PACE)":   STATUS_PHASE_ACCESS_CONTROL_PACE,
		"access control (BAC)":    STATUS_PHASE_ACCESS_CONTROL_BAC,
		"reading EF.DIR":          STATUS_PHASE_READING_DIR,
		"reading security object": STATUS_PHASE_READING_SECURITY_OBJECT,
		"reading common data":     STATUS_PHASE_READING_COMMON_DATA,
		"reading data group":      STATUS_PHASE_READING_DATA_GROUP,
		"active authentication":   STATUS_PHASE_ACTIVE_AUTHENTICATION,
		"chip authentication":     STATUS_PHASE_CHIP_AUTHENTICATION,
		"verifying document":      STATUS_PHASE_VERIFYING_DOCUMENT,
		"passive authentication":  STATUS_PHASE_PASSIVE_AUTHENTICATION,
		"finished":                STATUS_PHASE_FINISHED,
	}

	if !reflect.DeepEqual(act, exp) {
		t.Errorf("phase values differ to expected (act:%v) (exp:%v)", act, exp)
	}
}

// the engine's typed status has to arrive at the host as the phase and, for a
// data-group read, the data-group number
func TestReaderStatusAdapter(t *testing.T) {
	tests := []struct {
		name   string
		status reader.Status
		exp    [2]int
	}{
		{"phase only", reader.Status{Phase: reader.STATUS_PHASE_CONNECTING}, [2]int{STATUS_PHASE_CONNECTING, 0}},
		{"data group", reader.Status{Phase: reader.STATUS_PHASE_READING_DATA_GROUP, DataGroup: 7}, [2]int{STATUS_PHASE_READING_DATA_GROUP, 7}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hostStatus := &testReaderStatus{}

			(&readerStatusAdapter{status: hostStatus}).Status(tc.status)

			exp := [][2]int{tc.exp}
			if act := hostStatus.Recorded(); !reflect.DeepEqual(act, exp) {
				t.Errorf("recorded statuses differ to expected (act:%v) (exp:%v)", act, exp)
			}
		})
	}
}

// NB basic test that will fail quickly due to static transceiver. SelectMF tolerates its
// own (empty-response) error, so the read proceeds one phase further before failing on the
// next real exchange (reading EF.CardAccess).
func TestReadDocumentReportsStatus(t *testing.T) {
	status := &testReaderStatus{}

	rdr := NewReader(status, &iso7816.StaticTransceiver{})

	pass, err := NewPasswordCan("123456")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if _, err = rdr.ReadDocument(pass, nil, nil); err == nil {
		t.Fatalf("expected error")
	}

	exp := [][2]int{{STATUS_PHASE_CONNECTING, 0}, {STATUS_PHASE_READING_CARD_ACCESS, 0}}
	if act := status.Recorded(); !reflect.DeepEqual(act, exp) {
		t.Errorf("recorded statuses differ to expected (act:%v) (exp:%v)", act, exp)
	}
}

// NB basic test that will fail quickly due to static transceiver
func TestReadDocument(t *testing.T) {
	reader := NewReader(&testReaderStatus{}, &iso7816.StaticTransceiver{})

	reader.SetApduMaxLe(1000)

	pass, err := NewPasswordMrz("I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<8")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	doc, err := reader.ReadDocument(pass, nil, nil)
	if err == nil {
		t.Fatalf("expected error")
	}

	// attempt to get JSON data even though we expected document reading error
	// - we should still have some document object
	{
		json, jsonErr := doc.DocumentExJson()

		if jsonErr != nil {
			t.Errorf("unexpected error: %s", jsonErr)
		}

		if len(json) < 1 {
			t.Errorf("expected some JSON data")
		}
	}
}

func TestGetCscaCertPool(t *testing.T) {
	certPool, err := getCscaCertPool()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if certPool == nil {
		t.Fatalf("expected non-nil certPool")
	}
}

func TestPreloadCscaCertPool(t *testing.T) {
	err := PreloadCscaCertPool()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestDocumentExCborError(t *testing.T) {
	doc := &Document{}

	_, err := doc.DocumentExCbor()
	if err == nil {
		t.Error("expected error when documentEx is nil")
	}
}

func TestDocumentExCborRoundTrip(t *testing.T) {
	doc := &Document{documentEx: &document.DocumentEx{}}

	cborData, err := doc.DocumentExCbor()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(cborData) == 0 {
		t.Fatal("expected non-empty CBOR data")
	}
}

func TestVerifierVerifyInvalidInput(t *testing.T) {
	v := NewVerifier()

	_, err := v.Verify([]byte{0xff, 0xff, 0xff})
	if err == nil {
		t.Error("expected error for invalid CBOR input")
	}
}

func TestVerifierWithAAChallenge(t *testing.T) {
	t.Run("valid 8 bytes", func(t *testing.T) {
		v, err := NewVerifier().WithAAChallenge(make([]byte, 8))
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if v == nil {
			t.Errorf("expected non-nil verifier")
		}
	})

	invalidSizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"7 bytes", 7},
		{"9 bytes", 9},
		{"16 bytes", 16},
	}
	for _, tc := range invalidSizes {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewVerifier().WithAAChallenge(make([]byte, tc.size))
			if err == nil {
				t.Errorf("expected error for challenge of length %d", tc.size)
			}
		})
	}
}

func TestDocumentExJsonError(t *testing.T) {
	// error expected as we attempt to get Document-Json before ReadDocument

	doc := &Document{}

	_, err := doc.DocumentExJson()
	if err == nil {
		t.Errorf("error expected")
	}
}

func TestSummaryJsonError(t *testing.T) {
	// error expected as we attempt to get Summary-Json before ReadDocument

	doc := &Document{}

	_, err := doc.SummaryJson()
	if err == nil {
		t.Errorf("error expected")
	}
}

type PanicTransceiver struct {
}

func (t *PanicTransceiver) Transceive(cla, ins, p1, p2 int, data []byte, le int, rapdu []byte) []byte {
	panic("Transceiver that always panics")
}

func TestReadDocumentNilPassword(t *testing.T) {
	// panicTranseiver should never fire, as we won't get that far
	reader := NewReader(&testReaderStatus{}, &PanicTransceiver{})

	// pass in invalid Password (nil) to trigger panic, should get error
	var pass *MrtdPassword = nil

	_, err := reader.ReadDocument(pass, nil, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestCountryName(t *testing.T) {
	tests := []struct {
		name      string
		mrzAlpha3 string
		wantName  string
		wantErr   bool
	}{
		{name: "standard alpha-3", mrzAlpha3: "GBR", wantName: "United Kingdom"},
		{name: "standard alpha-3 lowercase", mrzAlpha3: "gbr", wantName: "United Kingdom"},
		{name: "germany special code D", mrzAlpha3: "D", wantName: "Germany"},
		{name: "germany standard DEU", mrzAlpha3: "DEU", wantName: "Germany"},
		{name: "unknown code", mrzAlpha3: "XXX", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CountryName(tt.mrzAlpha3)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			if got != tt.wantName {
				t.Fatalf("got %q, want %q", got, tt.wantName)
			}
		})
	}
}

func TestOidDesc(t *testing.T) {
	tests := []struct {
		name     string
		oidStr   string
		wantName string
	}{
		{name: "known OID", oidStr: "2.23.136.1.1.1", wantName: "ldsSecurityObject"},
		{name: "known OID bsi-de", oidStr: "0.4.0.127.0.7", wantName: "bsi-de"},
		{name: "unknown OID", oidStr: "1.2.3.4.5.6.7.8.9", wantName: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := OidDesc(tt.oidStr)

			if got != tt.wantName {
				t.Fatalf("got %q, want %q", got, tt.wantName)
			}
		})
	}
}

func TestNewSampleDocument(t *testing.T) {
	doc, err := NewSampleDocument()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	// Passive Authentication is run against the sample data, but is expected
	// to fail - the DGs are sourced from different worked examples.
	session := doc.documentEx.Session
	if session.PassiveAuthResult == nil {
		t.Fatalf("expected PassiveAuthResult to be populated")
	}
	if session.PassiveAuthResult.Success {
		t.Errorf("expected PassiveAuthResult.Success to be false")
	}
	if session.PassiveAuthErr == nil {
		t.Errorf("expected PassiveAuthErr to be set")
	}

	summary := doc.documentEx.Summary()
	if summary == nil || summary.DataTrusted {
		t.Errorf("expected Summary.DataTrusted to be false")
	}

	summaryJson, err := doc.SummaryJson()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(summaryJson) < 1 {
		t.Error("expected some Summary JSON data")
	}

	json, err := doc.DocumentExJson()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(json) < 1 {
		t.Error("expected some JSON data")
	}

	cborData, err := doc.DocumentExCbor()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(cborData) < 1 {
		t.Error("expected some CBOR data")
	}

	apduLogJson, err := doc.ApduLogJson()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(apduLogJson) < 1 {
		t.Error("expected some (empty-log) APDU log JSON data")
	}
}

// Regression test for a heap-corruption crash observed under concurrent use
// on iOS: a shared mobile.Reader's fields (maxRead/skipPace/skipImages/
// aaChallenge) were written by the configuration methods while ReadDocument
// read them from another goroutine, unsynchronised - exactly the kind of
// race that manifests as a Go runtime fatal error (e.g.
// "bulkBarrierPreWrite: unaligned arguments") rather than a clean panic. Run
// with `go test -race` to confirm the mutex added to Reader closes the race.
func TestReaderConcurrentAccess(t *testing.T) {
	reader := NewReader(&testReaderStatus{}, &iso7816.StaticTransceiver{})

	pass, err := NewPasswordMrz("I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<8")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = reader.SetApduMaxLe(1000)
			reader.SkipPace()
			reader.SkipImages()
			_, _ = reader.WithAAChallenge(make([]byte, 8))
			_, _ = reader.ReadDocument(pass, nil, nil) // expected to fail fast (static transceiver)
		}()
	}
	wg.Wait()
}

// Regression test for the same class of race as TestReaderConcurrentAccess,
// but for mobile.Verifier's aaChallenge field.
func TestVerifierConcurrentAccess(t *testing.T) {
	v := NewVerifier()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = v.WithAAChallenge(make([]byte, 8))
			_, _ = v.Verify([]byte{0xff, 0xff, 0xff}) // expected to fail fast (invalid CBOR)
		}()
	}
	wg.Wait()
}

func TestVersion(t *testing.T) {
	version := Version()

	// exected format: <major>.<minor>.<patch>
	var semverRegex = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`)

	if !semverRegex.MatchString(version) {
		t.Errorf("invalid version format: %s", version)
	}
}

// a host application that passes null for the ReaderStatus must still get the real
// error back, not the nil dereference from reporting the first phase
func TestReadDocumentNilStatusReportsRealError(t *testing.T) {
	rdr := NewReader(nil, &iso7816.StaticTransceiver{})

	pass, err := NewPasswordCan("123456")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if _, err = rdr.ReadDocument(pass, nil, nil); err == nil {
		t.Fatalf("expected error")
	}

	if strings.Contains(err.Error(), "nil pointer") {
		t.Errorf("nil ReaderStatus masked the read error (act:%s)", err)
	}
}
