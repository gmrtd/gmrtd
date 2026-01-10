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

type testReaderStatus struct {
}

func (status *testReaderStatus) Status(_ string) {
}

// NB basic test that will fail quickly due to static transceiver
func TestReadDocument(t *testing.T) {
	reader := NewReader(&testReaderStatus{})

	reader.SetApduMaxLe(1000)

	pass, err := NewPasswordMrz("I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<8")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	err = reader.ReadDocument(&iso7816.StaticTransceiver{}, pass, nil, nil)
	if err == nil {
		t.Fatalf("expected error")
	}

	// attempt to get JSON data even though we expected document reading error
	// - we should still have some document object
	{
		json, jsonErr := reader.DocumentJson()

		if jsonErr != nil {
			t.Errorf("unexpected error: %s", jsonErr)
		}

		if len(json) < 1 {
			t.Errorf("expected some JSON data")
		}
	}
}

func TestDocumentJsonError(t *testing.T) {
	// error expected as we attempt to get Document-Json before ReadDocument

	reader := NewReader(&testReaderStatus{})

	_, err := reader.DocumentJson()
	if err == nil {
		t.Errorf("error expected")
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
