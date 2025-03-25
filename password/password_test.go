package password

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestNewPasswordMrzTD2(t *testing.T) {
	pass, err := NewPasswordMrz("I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<8")
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if (pass.PasswordType != PASSWORD_TYPE_MRZi) || (pass.Password != "D23145890734934071279507122") {
		t.Errorf("Password (MRZ) not encoded correctly")
	}
}

func TestNewPasswordMrzInvalid(t *testing.T) {
	password, err := NewPasswordMrz("InvalidMrzStr")
	if err == nil {
		t.Errorf("Expected error, but got success")
	}

	if password != nil {
		t.Errorf("Unexpected password object")
	}
}

func TestNewPasswordMrzi(t *testing.T) {
	var err error
	var pass *Password

	pass, err = NewPasswordMrzi("D23145890734", "340712", "950712")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if (pass.PasswordType != PASSWORD_TYPE_MRZi) || (pass.Password != "D23145890734934071279507122") {
		t.Errorf("Password (MRZi) not encoded correctly")
	}
}

func TestNewPasswordCan(t *testing.T) {
	var pass *Password = NewPasswordCan("123456")
	if (pass.PasswordType != PASSWORD_TYPE_CAN) || (pass.Password != "123456") {
		t.Errorf("Password (CAN) not encoded correctly")
	}
}

func TestGetTypeAndKey1(t *testing.T) {
	var err error
	var pass *Password
	pass, err = NewPasswordMrzi("123456789", "820101", "291225")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	var expType byte = 1
	var expKey []byte = utils.HexToBytes("0ec557e7048cc90d31ec67599524b297adc33082")

	actType := pass.GetType()

	if actType != expType {
		t.Errorf("Password Type differs to expected (exp:%d, act:%d)", expType, actType)
	}

	actKey := pass.GetKey()

	if !bytes.Equal(actKey, expKey) {
		t.Errorf("Password Key differs to expected (exp:%x, act:%x)", expKey, actKey)
	}
}

func TestGetTypeAndKey2(t *testing.T) {
	var pass *Password = NewPasswordCan("123456")

	var expType byte = 2
	var expKey []byte = []byte("123456")

	actType := pass.GetType()

	if actType != expType {
		t.Errorf("Password Type differs to expected (exp:%d, act:%d)", expType, actType)
	}

	actKey := pass.GetKey()

	if !bytes.Equal(actKey, expKey) {
		t.Errorf("Password Key differs to expected (exp:%x, act:%x)", expKey, actKey)
	}
}

func TestGetKeyBadTypeErr(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	// trigger an error with an invalid password-type (99)
	var pass *Password = &Password{PasswordType: 99, Password: "BadPasswordType"}

	_ = pass.GetKey()

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}
