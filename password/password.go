// Package password provides utilities for generating MRTD passwords (MRZ,MRZi,CAN) used during BAC/PACE authentication.
package password

import "github.com/gmrtd/gmrtd/mrz"

type PasswordType int

const (
	PASSWORD_TYPE_MRZi PasswordType = iota
	PASSWORD_TYPE_CAN
)

type Password struct {
	PasswordType PasswordType
	Password     string
}

func NewPasswordMrz(mrzStr string) (pass *Password, err error) {
	pass = new(Password)
	pass.PasswordType = PASSWORD_TYPE_MRZi

	var m *mrz.MRZ
	m, err = mrz.MrzDecode(mrzStr)
	if err != nil {
		return nil, err
	}

	pass.Password = m.EncodeMrzi()

	return pass, err
}

func NewPasswordMrzi(documentNo string, dateOfBirth string, dateOfExpiry string) *Password {
	var out Password

	out.PasswordType = PASSWORD_TYPE_MRZi

	var mrz *mrz.MRZ = &mrz.MRZ{}

	mrz.DocumentNumber = documentNo
	mrz.DateOfBirth = dateOfBirth
	mrz.DateOfExpiry = dateOfExpiry

	out.Password = mrz.EncodeMrzi()

	return &out
}

func NewPasswordCan(can string) *Password {
	var out Password
	out.PasswordType = PASSWORD_TYPE_CAN
	out.Password = can
	return &out
}
