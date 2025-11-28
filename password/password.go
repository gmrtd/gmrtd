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
	PASSWORD_TYPE_NIL PasswordType = iota
	PASSWORD_TYPE_MRZi
	PASSWORD_TYPE_CAN
)

type Password struct {
	PasswordType PasswordType
	Password     string
}

// 'nil' password - used primarily by unit tests
func NewPasswordNil() *Password {
	var out Password
	out.PasswordType = PASSWORD_TYPE_NIL
	out.Password = ""
	return &out
}

func NewPasswordMrz(mrzStr string) (pass *Password, err error) {
	pass = new(Password)
	pass.PasswordType = PASSWORD_TYPE_MRZi

	var m *mrz.MRZ
	m, err = mrz.MrzDecode(mrzStr)
	if err != nil {
		return nil, err
	}

	pass.Password, err = m.EncodeMrzi()
	if err != nil {
		return nil, err
	}

	return pass, err
}

func NewPasswordMrzi(documentNo, dateOfBirth, dateOfExpiry string) (pass *Password, err error) {
	pass = new(Password)
	pass.PasswordType = PASSWORD_TYPE_MRZi

	var mrz *mrz.MRZ = &mrz.MRZ{}

	mrz.DocumentNumber = documentNo
	mrz.DateOfBirth = dateOfBirth
	mrz.DateOfExpiry = dateOfExpiry

	pass.Password, err = mrz.EncodeMrzi()
	if err != nil {
		return nil, err
	}

	return pass, nil
}

func NewPasswordCan(can string) *Password {
	var out Password
	out.PasswordType = PASSWORD_TYPE_CAN
	out.Password = can
	return &out
}

func (password *Password) Type() byte {
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

func (password *Password) Key() []byte {
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
		panic(fmt.Sprintf("[Key] Unsupported password-type (type:%d)", password.PasswordType))
	}

	return key
}
