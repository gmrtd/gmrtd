package gmrtd

type PasswordType int

const (
	PASSWORD_TYPE_MRZi PasswordType = iota
	PASSWORD_TYPE_CAN
)

type Password struct {
	passwordType PasswordType
	password     string
}

func NewPasswordMrz(mrzStr string) (pass *Password, err error) {
	pass = new(Password)
	pass.passwordType = PASSWORD_TYPE_MRZi

	var mrz *MRZ
	mrz, err = MrzDecode(mrzStr)
	if err != nil {
		return nil, err
	}

	pass.password = mrz.EncodeMrzi()

	return pass, err
}

func NewPasswordMrzi(documentNo string, dateOfBirth string, dateOfExpiry string) *Password {
	var out Password

	out.passwordType = PASSWORD_TYPE_MRZi

	var mrz *MRZ = &MRZ{}

	mrz.DocumentNumber = documentNo
	mrz.DateOfBirth = dateOfBirth
	mrz.DateOfExpiry = dateOfExpiry

	out.password = mrz.EncodeMrzi()

	return &out
}

func NewPasswordCan(can string) *Password {
	var out Password
	out.passwordType = PASSWORD_TYPE_CAN
	out.password = can
	return &out
}
