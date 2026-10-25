package mobile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/reader"
	"github.com/gmrtd/gmrtd/utils"
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

func TestAllowBacFallbackOnPaceError(t *testing.T) {
	reader := &Reader{}

	if reader.allowBacFallbackOnPaceError {
		t.Fatalf("allowBacFallbackOnPaceError should default to false")
	}

	reader.AllowBacFallbackOnPaceError()

	if !reader.allowBacFallbackOnPaceError {
		t.Fatalf("allowBacFallbackOnPaceError should be true after calling AllowBacFallbackOnPaceError()")
	}
}

func TestRequireAuthenticDocument(t *testing.T) {
	reader := &Reader{}

	if reader.requireAuthenticDocument {
		t.Fatalf("requireAuthenticDocument should default to false")
	}

	reader.RequireAuthenticDocument()

	if !reader.requireAuthenticDocument {
		t.Fatalf("requireAuthenticDocument should be true after calling RequireAuthenticDocument()")
	}
}

func TestRejectedDocumentHelper(t *testing.T) {
	doc := &Document{}

	testCases := []struct {
		name string
		err  error
		exp  *Document
	}{
		{"not authentic", fmt.Errorf("[ReadDocument] runSteps error: %w", fmt.Errorf("[checkAuthenticDocument] %w: data not trusted", reader.ErrDocumentNotAuthentic)), doc},
		{"other read error", errors.New("[ReadDocument] runSteps error: transceive failed"), nil},
		{"no error", nil, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if act := rejectedDocument(doc, tc.err); act != tc.exp {
				t.Errorf("rejectedDocument (act:%p) (exp:%p)", act, tc.exp)
			}
		})
	}
}

func TestRejectedDocumentClearedByReadDocument(t *testing.T) {
	rdr := NewReader(&testReaderStatus{}, &iso7816.StaticTransceiver{})
	rdr.RequireAuthenticDocument()

	if rdr.RejectedDocument() != nil {
		t.Fatalf("RejectedDocument should default to nil")
	}

	rdr.rejectedDocument = &Document{}

	pass, err := NewPasswordCan("123456")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	// fails before the authenticity check (static transceiver), so nothing is rejected
	if _, err := rdr.ReadDocument(pass, nil, nil); err == nil {
		t.Fatalf("expected error")
	}

	if rdr.RejectedDocument() != nil {
		t.Errorf("RejectedDocument should be nil after a read that failed for another reason")
	}
}

func TestNewGmrtdReaderInvalidAAChallenge(t *testing.T) {
	// WithAAChallenge rejects a bad length up front, so set the field directly to reach the
	// defensive check in the underlying reader.
	r := &Reader{aaChallenge: make([]byte, 3)}

	if _, err := r.newGmrtdReader(iso7816.NewNfcSession(&iso7816.StaticTransceiver{}), &cms.GenericCertPool{}); err == nil {
		t.Fatalf("expected error for invalid AA challenge")
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
// requireAuthenticDocument/aaChallenge/rejectedDocument) were written by the configuration methods while ReadDocument
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
			reader.AllowBacFallbackOnPaceError()
			reader.RequireAuthenticDocument()
			_, _ = reader.WithAAChallenge(make([]byte, 8))
			_, _ = reader.ReadDocument(pass, nil, nil) // expected to fail fast (static transceiver)
			_ = reader.RejectedDocument()
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

func TestVerifierWithTrustedSource(t *testing.T) {
	var empty document.DocumentEx
	data, err := empty.ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error: %s", err)
	}

	for _, trusted := range []bool{false, true} {
		v := NewVerifier()
		if trusted {
			v = v.WithTrustedSource()
		}

		doc, err := v.Verify(data)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		offline := doc.documentEx.Session.Offline
		if offline == nil || offline.TrustedSource != trusted {
			t.Errorf("Session.Offline = %+v, want TrustedSource=%v", offline, trusted)
		}
	}
}

// Same real fixture as verifier.TestVerifyRealDocumentGBR: the mobile Verifier must give the same
// verdict as the Go verifier.
func TestVerifierRealDocumentGBR(t *testing.T) {
	data, err := os.ReadFile("../verifier/testdata/GBR-099250692.gmrtd")
	if err != nil {
		t.Fatalf("ReadFile error: %s", err)
	}

	// the UK CSCA expired on 2026-07-24 and has since been dropped from the master lists
	defaultPool, err := getCscaCertPool()
	if err != nil {
		t.Fatalf("getCscaCertPool error: %s", err)
	}
	var ukCsca cms.GenericCertPool
	if err := ukCsca.Add(utils.HexToBytes("308205FA308203E2A0030201020204492EAE16300D06092A864886F70D01010B05003041310B3009060355040613026762310E300C060355040A1305554B4B50413122302006035504031319436F756E747279205369676E696E6720417574686F72697479301E170D3130303332343134303230315A170D3236303732343134333230315A3041310B3009060355040613026762310E300C060355040A1305554B4B50413122302006035504031319436F756E747279205369676E696E6720417574686F7269747930820222300D06092A864886F70D01010105000382020F003082020A0282020100C3583682D60EE9DB5E77F3CD27F02C8657ABA30C70A21EBC33FCAFA8E96B5806A090EF29CDC8A4A286F750C4F237CE89A207D460DED39854CFF2BA8F4E7807C655FE1B60E7459FF7E24DE2806EA6823BA8B3DD0A00C80B3DCB8BAE3C4620D9F5A81E3144E7805C96F147AFB13D6C9BAAB3D469EFCA9EADACAD81ED623FCCA82263D72350F553C17DE29352F937CA3EEFDAA902FE718EFC5F90CE9B35027E5F56CD92FDE396B2ACD2C8A83A7F5712CF7DF298607D072B8E82C5DD94BE323D293ADBD25B4F53467AAAE53E92BDD23E26B5501DA24B53E1F492917CA0FA8C59680FB17C952AC642944639B385A06315C251B204DD922E2F86A1D40F1FE3626E602D8D9ED0870C5D0E86ACB0E3845557E63CBB327D9EFFECD317A31FA337AEAC6F9304EB59B63DFEA4D7EC7AC94891D5D8B14F4FB4DB1AA4A88AD5B339FE7DCB460F8231F5B0628A6EA75C3FC252BF00C0D54D850D489346F3753A476A0EA237CAF9001CE729BB2EC2CEA6368F040A2B1B1108A2133EFFE4CA369D043D58A72D0AC1202138CCA1A370B26D576DA079DBDD6C59989F1E40F670AF27E28231ED3F7A5C7F1F699B9AB217F7125993CDA5C0B25147A0C37D08098B85D8B4F231303B1DF92EFAF03E31D92DE00D6971FD4D43971C318DCCB3F1FE908520F5AA788EADE562D0B23F85FF76340C5D181811B2C19529387807EBDD7C5AB09D971F0D3AB516AD0203010001A381F93081F6300E0603551D0F0101FF04040302010630120603551D130101FF040830060101FF02010030630603551D1F045C305A3058A056A054A4523050310B3009060355040613026762310E300C060355040A1305554B4B50413122302006035504031319436F756E747279205369676E696E6720417574686F72697479310D300B0603550403130443524C31302B0603551D1004243022800F32303130303332343134303230315A810F32303236303732343134333230315A301F0603551D230418301680144531A5B73BCF8BB27C7FAC88C74B4505F6C936B3301D0603551D0E041604144531A5B73BCF8BB27C7FAC88C74B4505F6C936B3300D06092A864886F70D01010B0500038202010054F23F6A723698B06338E7A37FB2C740506E2175970C76E20D629D0AB5557359360826E7A611B3748470C1E7995952547C1BB790F4899D258F9127F6C4730F5FF63A8498EAEB50FAF767283B73325B968B497E8C6361073EC25DA7E4C225F36E5870D5874F11BC102F4DC2FEE784F3B3CB9AF3BD3C55F5A72C1883EB2632153B16F594AA086D549228CF0013199D66899181BE47AC0EF37D5F4FE7CB23B8565CD7F4099968DD90791E8EAAE871914BB25C4ABC5556D8387D4964CD87051088431FC32AAC31E37DCEE14BA835C9618E1365216BD227563D99520FD03B101CA7EABFE326BA71B4DE40DA328B2F65E99B591B01FC132C9713BF525238FEDE68A509653C196AA73404D970509D7112EFBC62F385F9642DDE0FBFC7228E0AB388C69E0304B617CC56E4B6253FBD005B22AFF67420F51069AE8D2DC9E5F076E33016AA4E1BBE11A3B79CBA4E41002021639126B7DDC79DC6DF2CD2C1DDB706B825125514F8E5797C409B1B69A8EADA1E95E1FAD139F7C1E189008A5BAB74DF7E87830AF1FBDFC27BD1985CF8DFE5C631AA4F7C0D439D80FB35B34F7722FC0EFBD2B88B4C4BC918EE4E5BD868EB49E1B6858696B364BCEC7D69E494E7DA8198D69A6ABE1F31D01502F5E78550808C2F14CD447E0E56ACDF01A5A145C52EC867232091F1C71800654CC7529557C3414667F9711275B36E92196DD8D600587D4E93FD08D3")); err != nil {
		t.Fatalf("ukCsca.Add error: %s", err)
	}
	var pool cms.CombinedCertPool
	pool.AddCertPool(defaultPool)
	pool.AddCertPool(&ukCsca)
	cscaCertPool = &pool
	t.Cleanup(func() { cscaCertPool = defaultPool })

	doc, err := NewVerifier().Verify(data)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	summary := doc.documentEx.Summary()
	if !summary.DataTrusted {
		t.Errorf("expected DataTrusted (PassiveAuthErr=%v)", doc.documentEx.Session.PassiveAuthErr)
	}
	if summary.ChipAuthenticity != document.CHIP_AUTH_STATUS_NONE {
		t.Errorf("ChipAuthenticity = %v, want NONE", summary.ChipAuthenticity)
	}

	assertSummaryJsonTrustChain(t, doc, document.PASSIVE_AUTH_STATUS_VERIFIED, true, "CN=Document Signing Key 35, OU=london, O=ukps, C=gb")
}

func TestSampleDocumentSummaryJsonTrustChain(t *testing.T) {
	doc, err := NewSampleDocument()
	if err != nil {
		t.Fatalf("NewSampleDocument error: %s", err)
	}

	// Passive Authentication fails for the sample document, so only its unverified signer is shown
	assertSummaryJsonTrustChain(t, doc, document.PASSIVE_AUTH_STATUS_FAILED, false, "CN=DS-AUSTRIA-eMRTD, SERIALNUMBER=004015, OU=BMI, O=GV, C=AT")
}

// assertSummaryJsonTrustChain checks the trust chain as a mobile client receives it via SummaryJson.
func assertSummaryJsonTrustChain(t *testing.T, doc *Document, wantStatus document.PassiveAuthStatus, wantVerified bool, wantSigner string) {
	t.Helper()
	jsonData, err := doc.SummaryJson()
	if err != nil {
		t.Fatalf("SummaryJson error: %s", err)
	}

	var summary struct {
		PassiveAuth struct {
			Status string `json:"status"`
			Sod    struct {
				Verified bool `json:"verified"`
				Chain    []struct {
					Role    string `json:"role"`
					Subject string `json:"subject"`
				} `json:"chain"`
			} `json:"sod"`
		} `json:"passiveAuth"`
	}
	if err := json.Unmarshal(jsonData, &summary); err != nil {
		t.Fatalf("json.Unmarshal error: %s", err)
	}

	pa := summary.PassiveAuth
	if pa.Status != string(wantStatus) || pa.Sod.Verified != wantVerified || len(pa.Sod.Chain) < 1 {
		t.Fatalf("passiveAuth = %+v, want status %s, verified %v", pa, wantStatus, wantVerified)
	}
	if signer := pa.Sod.Chain[0]; signer.Role != string(document.CERTIFICATE_ROLE_DOCUMENT_SIGNER) || signer.Subject != wantSigner {
		t.Errorf("chain[0] = %s %q, want DOCUMENT_SIGNER %q", signer.Role, signer.Subject, wantSigner)
	}
}
