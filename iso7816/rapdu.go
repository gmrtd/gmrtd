package iso7816

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/gmrtd/gmrtd/utils"
)

// Status words (SW1-SW2) returned in R-APDUs (ISO/IEC 7816-4).
const (
	RAPDU_STATUS_SUCCESS                      = 0x9000
	RAPDU_STATUS_SELECTED_FILE_INVALIDATED    = 0x6283 // warning
	RAPDU_STATUS_WRONG_LENGTH                 = 0x6700
	RAPDU_SECURITY_CONDITION_NOT_SATIFIED     = 0x6982
	RAPDU_STATUS_FUNCTION_NOT_SUPPORTED       = 0x6A81
	RAPDU_STATUS_FILENOTFOUND                 = 0x6A82
	RAPDU_STATUS_INCORRECT_P1_OR_P2_PARAMETER = 0x6A86
	RAPDU_STATUS_LC_INCONSISTENT_WITH_P1P2    = 0x6A87 // Lc inconsistent with P1-P2
)

// RApdu is an ISO/IEC 7816-4 response APDU: the response data and the status word.
type RApdu struct {
	Data   []byte
	Status uint16
}

// NewRApdu returns an R-APDU with the given status word and data.
func NewRApdu(status uint16, data []byte) *RApdu {
	return &RApdu{Status: status, Data: data}
}

// String returns the status word and data in a readable form, for logging.
func (apdu *RApdu) String() string {
	return fmt.Sprintf("(Status:%04x, Data:%x)", apdu.Status, apdu.Data)
}

// IsSuccess reports whether the status word is 9000.
func (apdu *RApdu) IsSuccess() bool {
	return apdu.Status == RAPDU_STATUS_SUCCESS
}

// FileNotFound reports whether the status word is 6A82 (file or application not found).
func (apdu *RApdu) FileNotFound() bool {
	return apdu.Status == RAPDU_STATUS_FILENOTFOUND
}

// ParseRApdu parses an encoded R-APDU, taking the last 2 bytes as the status word and copying
// the rest as the data. It returns an error if data is shorter than 2 bytes.
func ParseRApdu(data []byte) (rapdu *RApdu, err error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("rApdu length must be >= 2 (Length:%d)", len(data))
	}

	rapdu = new(RApdu)

	rapdu.Status = binary.BigEndian.Uint16(data[len(data)-2:])

	rapdu.Data = make([]byte, len(data)-2)
	copy(rapdu.Data, data[0:len(data)-2])

	return rapdu, nil
}

// Encode returns the encoded R-APDU: the data followed by the 2-byte status word.
func (rApdu *RApdu) Encode() []byte {
	var out []byte
	out = bytes.Clone(rApdu.Data)
	out = append(out, utils.UInt16ToBytes(rApdu.Status)...)
	return out
}
