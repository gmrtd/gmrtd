package password

import "testing"

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
	var pass *Password = NewPasswordMrzi("D23145890734", "340712", "950712")
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
