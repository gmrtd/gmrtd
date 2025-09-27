package mobile

import (
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

func (status *testReaderStatus) Status(msg string) {
}

// TODO -  basic test that will fail quickly due to static transceiver
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
}
