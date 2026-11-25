// Package password provides utilities for generating MRTD passwords (MRZ,MRZi,CAN) used during BAC/PACE authentication.
//
// "Password" is not a user-chosen login credential - it's the ICAO 9303 term for a shared
// secret that proves the reader has physical/optical access to the document itself. It's
// one of:
//   - MRZi: derived from the document number, date of birth, and date of expiry printed in
//     the MRZ (see NewPasswordMrz / NewPasswordMrzi).
//   - CAN: the Card Access Number, a short number printed on the document (see NewPasswordCan).
//
// PACE takes its name directly from this term: "Password Authenticated Connection
// Establishment" (9303 p11 s4). BAC uses the same secret to derive its session keys, which
// the spec calls the "Basic Access Keys" (KEnc/KMAC) - see Password.Key.
package password

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/mrz"
)

var (
	// ErrPasswordTypeUnsupported is returned by Password.Type and Password.Key for a
	// password type other than MRZi or CAN (e.g. PASSWORD_TYPE_NIL).
	ErrPasswordTypeUnsupported = errors.New("Password.Type is unsupported")
)

// PasswordType identifies the kind of secret a Password holds.
type PasswordType int

const (
	// PASSWORD_TYPE_NIL is an empty password that cannot be used for BAC or PACE.
	PASSWORD_TYPE_NIL PasswordType = iota
	// PASSWORD_TYPE_MRZi is an MRZ information password, usable for BAC and PACE.
	PASSWORD_TYPE_MRZi
	// PASSWORD_TYPE_CAN is a Card Access Number password, usable for PACE only.
	PASSWORD_TYPE_CAN
)

// Password holds the shared secret (MRZi or CAN) used to authenticate with the document
// chip. It is not a login password; see the package doc comment for the ICAO 9303 context.
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

// NewPasswordMrz derives an MRZi password from a raw MRZ string.
// ConvertMrzToMrzi is used instead of MrzDecode+EncodeMrzi so that only the three
// fields required to construct the MRZi (document number, date of birth, date of
// expiry) are validated. The composite check digit and all other MRZ fields are
// ignored, making this tolerant of OCR noise outside those three fields.
func NewPasswordMrz(mrzStr string) (pass *Password, err error) {
	pass = new(Password)
	pass.PasswordType = PASSWORD_TYPE_MRZi

	pass.Password, err = mrz.ConvertMrzToMrzi(mrzStr)
	if err != nil {
		return nil, err
	}

	return pass, nil
}

// NewPasswordMrzi builds an MRZi password from the document number, date of birth and date
// of expiry (YYMMDD), padding with '<' and appending the computed check digits.
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

// NewPasswordCan returns a CAN password holding can as given, without validation.
func NewPasswordCan(can string) *Password {
	var out Password
	out.PasswordType = PASSWORD_TYPE_CAN
	out.Password = can
	return &out
}

// Type returns the password reference sent to the chip in PACE MSE:Set AT: 1 for MRZi and
// 2 for CAN. Any other type returns an error wrapping ErrPasswordTypeUnsupported.
func (password *Password) Type() (byte, error) {
	// manually convert value to reduce reliance on iota values!
	var passwordTypeValue byte

	switch password.PasswordType {
	case PASSWORD_TYPE_MRZi:
		passwordTypeValue = 1
	case PASSWORD_TYPE_CAN:
		passwordTypeValue = 2
	default:
		return 0, fmt.Errorf("%w: %d", ErrPasswordTypeUnsupported, password.PasswordType)
	}

	return passwordTypeValue, nil
}

// Key returns the raw secret bytes derived from the password (SHA1(MRZi) or the CAN
// itself). This is an input to BAC/PACE key derivation (e.g. K_seed), not a final
// session key on its own.
func (password *Password) Key() ([]byte, error) {
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
		return nil, fmt.Errorf("%w: %d", ErrPasswordTypeUnsupported, password.PasswordType)
	}

	return key, nil
}
