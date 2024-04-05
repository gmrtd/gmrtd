package gmrtd

import "testing"

func TestNewPasswordMrzTD2(t *testing.T) {
	var password *Password = NewPasswordMrz("I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<D23145890<UTO3407127M95071227349<<<8")
	if (password.passwordType != PASSWORD_TYPE_MRZi) || (password.password != "D23145890734934071279507122") {
		t.Errorf("Password (MRZ) not encoded correctly")
	}
}

func TestNewPasswordMrzi(t *testing.T) {
	var password *Password = NewPasswordMrzi("D23145890734", "340712", "950712")
	if (password.passwordType != PASSWORD_TYPE_MRZi) || (password.password != "D23145890734934071279507122") {
		t.Errorf("Password (MRZi) not encoded correctly")
	}
}

func TestNewPasswordCan(t *testing.T) {
	var password *Password = NewPasswordCan("123456")
	if (password.passwordType != PASSWORD_TYPE_CAN) || (password.password != "123456") {
		t.Errorf("Password (CAN) not encoded correctly")
	}
}
