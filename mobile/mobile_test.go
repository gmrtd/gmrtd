package mobile

import (
	"regexp"
	"testing"

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

func TestVersion(t *testing.T) {
	version := Version()

	// exected format: <major>.<minor>.<patch>
	var semverRegex = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`)

	if !semverRegex.MatchString(version) {
		t.Errorf("invalid version format: %s", version)
	}
}
