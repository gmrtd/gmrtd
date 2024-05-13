package gmrtd

import (
	"encoding/binary"
	"fmt"
)

const RAPDU_STATUS_SUCCESS = 0x9000
const RAPDU_STATUS_FILENOTFOUND = 0x6A82

type RApdu struct {
	Data   []byte
	Status uint16
}

func NewRApdu(status uint16, data []byte) *RApdu {
	return &RApdu{Status: status, Data: data}
}

func (apdu *RApdu) String() string {
	return fmt.Sprintf("(Status:%04x, Data:%x)", apdu.Status, apdu.Data)
}

func (apdu *RApdu) IsSuccess() bool {
	return apdu.Status == RAPDU_STATUS_SUCCESS
}

func (apdu *RApdu) FileNotFound() bool {
	return apdu.Status == RAPDU_STATUS_FILENOTFOUND
}

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
