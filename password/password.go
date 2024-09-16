// Package password provides utilities for generating MRTD passwords (MRZ,MRZi,CAN) used during BAC/PACE authentication.
package password

import (
	"bytes"
	"crypto"
	"fmt"
	"log"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/mrz"
)

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

func (password *Password) GetType() byte {
	// manually convert value to reduce reliance on iota values!
	var passwordTypeValue byte

	switch password.PasswordType {
	case PASSWORD_TYPE_MRZi:
		passwordTypeValue = 1
	case PASSWORD_TYPE_CAN:
		passwordTypeValue = 2
	default:
		log.Panicf("unsupported PACE Password-Type (%x)", password.PasswordType)
	}

	return passwordTypeValue
}

func (password *Password) GetKey() []byte {
	// generate K
	var key []byte

	switch password.PasswordType {
	case PASSWORD_TYPE_MRZi:
		// k = SHA1(mrzi)
		key = cryptoutils.CryptoHash(crypto.SHA1, []byte(password.Password))
	case PASSWORD_TYPE_CAN:
		// k = CAN
		// NB spec claims that CAN is ISO 8859-1 encoded (9303p11 s9.7.3 PACE)
		//    - we're ignoring this as we don't expect extended characters
		key = bytes.Clone([]byte(password.Password))
	default:
		panic(fmt.Sprintf("[GetKey] Unsupported password-type (type:%d)", password.PasswordType))
	}

	return key
}
