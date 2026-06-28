package mobile

import (
	"regexp"
	"testing"

	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
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

type testReaderStatus struct {
}

func (status *testReaderStatus) Status(_ string) {
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
		name        string
		mrzAlpha3   string
		wantName    string
		wantErr     bool
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

func TestVersion(t *testing.T) {
	version := Version()

	// exected format: <major>.<minor>.<patch>
	var semverRegex = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`)

	if !semverRegex.MatchString(version) {
		t.Errorf("invalid version format: %s", version)
	}
}
