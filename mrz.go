package gmrtd

import (
	"fmt"
	"log"
	"log/slog"
	"strconv"
	"strings"
)

// TODO - check that MRZ only contains 0-9,A-Z and filler ('<')

type MrzName struct {
	Primary   string
	Secondary string // optional
}

type MRZ struct {
	DocumentCode   string
	IssuingState   string
	NameOfHolder   MrzName
	DocumentNumber string
	Nationality    string
	DateOfBirth    string
	Sex            string
	DateOfExpiry   string
	OptionalData   string
	OptionalData2  string // TODO - just required for TD1?.. should this be considered as a single logical field?
}

// "Type 3" is typical of passport booklets. The MRZ consists of 2 lines × 44 characters.
// "Type 2" is relatively rare with 2 lines × 36 characters.
// "Type 1" is of a credit card-size with 3 lines × 30 characters.

const MRZLengthTD1 = 90
const MRZLengthTD2 = 72
const MRZLengthTD3 = 88

// parses the name into primary and secondary (if present) components
// NB field separator is '  ' (double-space) as we've already converted '<' to ' ' earlier
func parseName(name string) MrzName {
	var out MrzName

	strArr := strings.Split(name, "  ")

	switch len(strArr) {
	case 1:
		out.Primary = strArr[0]
	case 2:
		out.Primary = strArr[0]
		out.Secondary = strArr[1]
	default:
		log.Panicf("Incorrect number of name components: %d", len(strArr))
	}

	return out
}

// min/maxLength can be -1
func encodeValue(value string, minLength int, maxLength int) string {
	// sanity check that maxLength >= minLength (where specified)
	if minLength != -1 && maxLength != -1 && maxLength < minLength {
		log.Panicf("Incorrect min/max values")
	}

	out := strings.ReplaceAll(value, " ", "<")

	// truncate (if too long)
	if maxLength != -1 && len(out) > maxLength {
		out = out[0:maxLength]
	}

	// right pad (if too short)
	if minLength != -1 && len(out) < minLength {
		out = out + strings.Repeat("<", minLength-len(out))
	}

	return out
}

func decodeValue(value string) string {
	decodedValue := value

	decodedValue = strings.ReplaceAll(decodedValue, "<", " ")
	decodedValue = strings.TrimRight(decodedValue, " ")

	return decodedValue
}

func MrzDecode(mrz string) (*MRZ, error) {
	switch len(mrz) {
	case MRZLengthTD1:
		return decodeTD1(mrz)
	case MRZLengthTD2:
		return decodeTD2(mrz)
	case MRZLengthTD3:
		return decodeTD3(mrz)
		//	default:
	}

	return nil, fmt.Errorf("unsupported MRZ length (length:%d)", len(mrz))
}

func calcCheckdigit(data string) int {
	weights := []byte{7, 3, 1}

	value := 0

	for i := 0; i < len(data); i++ {
		c := data[i]

		tmpValue := 0

		if c >= '0' && c <= '9' {
			tmpValue = int(c - '0')
		} else if c >= 'A' && c <= 'Z' {
			tmpValue = int(c - 'A' + 10)
		} else if (c == '<') || (c == ' ') {
			tmpValue = 0
		} else {
			log.Panicf("Invalid character (%c) for check-digit calculation", c)
		}

		tmpValue *= int(weights[i%len(weights)])

		value += tmpValue
	}

	value %= 10

	return value
}

func verifyCheckdigit(data string, checkDigit string) {
	// check for empty field with unset checkdigit
	if (checkDigit == "<") && (len(strings.Trim(data, "<")) == 0) {
		return
	}

	expCD := calcCheckdigit(data)
	actCD, err := strconv.Atoi(checkDigit)
	if err != nil {
		log.Panicf("Atoi error (checkdigit:%s)", checkDigit)
	}

	if expCD != actCD {
		log.Panicf("MRZ Checkdigit mismatch (Exp:%d, Act:%d, Data:%s)", expCD, actCD, data)
	}
}

// TODO - TD1/2 have similar handling for extended doc-no... maybe update to use shared code

func decodeTD1(mrz string) (*MRZ, error) {
	slog.Debug("decodeTD1", "MRZ", mrz)

	if len(mrz) != MRZLengthTD1 {
		return nil, fmt.Errorf("invalid MRZ TD1 length (Exp:%d) (Act:%d)", MRZLengthTD1, len(mrz))
	}

	// line 1
	documentCode := mrz[0:2]
	issuingState := mrz[2:5]
	documentNumber := mrz[5:14]
	documentNumberCD := mrz[14:15]
	optionalData := mrz[15:30]

	// line 2
	dateOfBirth := mrz[30:36]
	dateOfBirthCD := mrz[36:37]
	sex := mrz[37:38]
	dateOfExpiry := mrz[38:44]
	dateOfExpiryCD := mrz[44:45]
	nationality := mrz[45:48]
	optionalData2 := mrz[48:59]

	// line 3
	nameOfHolder := mrz[60:90]

	// special handling for 'extended' document-number (>9 characters)
	if documentNumberCD == "<" {
		tmpIdx := strings.Index(optionalData, "<")
		if tmpIdx < 2 {
			log.Panicf("Invalid encoding. Index must be >=2 (Act:%d)", tmpIdx)
		}

		documentNumber += optionalData[0 : tmpIdx-1]
		documentNumberCD = optionalData[tmpIdx-1 : tmpIdx]
		optionalData = optionalData[tmpIdx+1:]
	}

	out := &MRZ{}

	out.DocumentCode = decodeValue(documentCode)
	out.IssuingState = decodeValue(issuingState)
	out.DocumentNumber = decodeValue(documentNumber)
	verifyCheckdigit(documentNumber, documentNumberCD)
	out.OptionalData = decodeValue(optionalData)

	out.DateOfBirth = decodeValue(dateOfBirth)
	verifyCheckdigit(dateOfBirth, dateOfBirthCD)
	out.Sex = decodeValue(sex)
	out.DateOfExpiry = decodeValue(dateOfExpiry)
	verifyCheckdigit(dateOfExpiry, dateOfExpiryCD)
	out.Nationality = decodeValue(nationality)
	out.OptionalData2 = decodeValue(optionalData2)

	// composite check digit
	verifyCheckdigit(mrz[5:30]+mrz[30:37]+mrz[38:45]+mrz[48:59], mrz[59:60])

	out.NameOfHolder = parseName(decodeValue(nameOfHolder))

	return out, nil
}

func decodeTD2(mrz string) (*MRZ, error) {
	slog.Debug("decodeTD2", "MRZ", mrz)

	if len(mrz) != MRZLengthTD2 {
		return nil, fmt.Errorf("invalid MRZ TD2 length (Exp:%d) (Act:%d)", MRZLengthTD2, len(mrz))
	}

	// line 1
	documentCode := mrz[0:2]
	issuingState := mrz[2:5]
	nameOfHolder := mrz[5:36]

	// line 2
	documentNumber := mrz[36:45]
	documentNumberCD := mrz[45:46]
	nationality := mrz[46:49]
	dateOfBirth := mrz[49:55]
	dateOfBirthCD := mrz[55:56]
	sex := mrz[56:57]
	dateOfExpiry := mrz[57:63]
	dateOfExpiryCD := mrz[63:64]
	optionalData := mrz[64:71]

	// special handling for 'extended' document-number (>9 characters)
	if documentNumberCD == "<" {
		tmpIdx := strings.Index(optionalData, "<")
		if tmpIdx < 2 {
			log.Panicf("Invalid encoding. Index must be >=2 (Act:%d)", tmpIdx)
		}

		documentNumber += optionalData[0 : tmpIdx-1]
		documentNumberCD = optionalData[tmpIdx-1 : tmpIdx]
		optionalData = optionalData[tmpIdx+1:]
	}

	out := &MRZ{}

	out.DocumentCode = decodeValue(documentCode)
	out.IssuingState = decodeValue(issuingState)
	out.NameOfHolder = parseName(decodeValue(nameOfHolder))

	out.DocumentNumber = decodeValue(documentNumber)
	verifyCheckdigit(documentNumber, documentNumberCD)
	out.Nationality = decodeValue(nationality)
	out.DateOfBirth = decodeValue(dateOfBirth)
	verifyCheckdigit(dateOfBirth, dateOfBirthCD)
	out.Sex = decodeValue(sex)
	out.DateOfExpiry = decodeValue(dateOfExpiry)
	verifyCheckdigit(dateOfExpiry, dateOfExpiryCD)
	out.OptionalData = decodeValue(optionalData)

	// composite check digit
	verifyCheckdigit(mrz[36:46]+mrz[49:56]+mrz[57:71], mrz[71:72])

	return out, nil
}

func decodeTD3(mrz string) (*MRZ, error) {
	slog.Debug("decodeTD3", "MRZ", mrz)

	if len(mrz) != MRZLengthTD3 {
		return nil, fmt.Errorf("invalid MRZ TD3 length (Exp:%d) (Act:%d)", MRZLengthTD3, len(mrz))
	}

	// line 1
	documentCode := mrz[0:2]
	issuingState := mrz[2:5]
	nameOfHolder := mrz[5:44]

	// line 2
	documentNumber := mrz[44:53]
	documentNumberCD := mrz[53:54]
	nationality := mrz[54:57]
	dateOfBirth := mrz[57:63]
	dateOfBirthCD := mrz[63:64]
	sex := mrz[64:65]
	dateOfExpiry := mrz[65:71]
	dateOfExpiryCD := mrz[71:72]
	optionalData := mrz[72:86]
	optionalDataCD := mrz[86:87]

	out := &MRZ{}

	out.DocumentCode = decodeValue(documentCode)
	out.IssuingState = decodeValue(issuingState)
	out.NameOfHolder = parseName(decodeValue(nameOfHolder))

	out.DocumentNumber = decodeValue(documentNumber)
	verifyCheckdigit(documentNumber, documentNumberCD)
	out.Nationality = decodeValue(nationality)
	out.DateOfBirth = decodeValue(dateOfBirth)
	verifyCheckdigit(dateOfBirth, dateOfBirthCD)
	out.Sex = decodeValue(sex)
	out.DateOfExpiry = decodeValue(dateOfExpiry)
	verifyCheckdigit(dateOfExpiry, dateOfExpiryCD)
	out.OptionalData = decodeValue(optionalData)
	verifyCheckdigit(optionalData, optionalDataCD)

	// composite check digit
	verifyCheckdigit(mrz[44:54]+mrz[57:64]+mrz[65:87], mrz[87:88])

	return out, nil
}

func (mrz *MRZ) EncodeMrzi() string {
	// [9] document-number
	documentNumber := encodeValue(mrz.DocumentNumber, 9, -1)
	// [1] check-digit
	documentNumberCD := strconv.Itoa(calcCheckdigit(documentNumber))
	// [6] date-of-birth
	dateOfBirth := encodeValue(mrz.DateOfBirth, 6, 6)
	// [1] check-digit
	dateOfBirthCD := strconv.Itoa(calcCheckdigit(dateOfBirth))
	// [6] date-of-expiry
	dateOfExpiry := encodeValue(mrz.DateOfExpiry, 6, 6)
	// [1] check-digit
	dateOfExpiryCD := strconv.Itoa(calcCheckdigit(dateOfExpiry))

	out := documentNumber + documentNumberCD + dateOfBirth + dateOfBirthCD + dateOfExpiry + dateOfExpiryCD

	slog.Debug("MrzEncodeMRZi", "MRZi", out)

	return out
}
