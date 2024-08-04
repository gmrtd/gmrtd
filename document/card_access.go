package document

import (
	"slices"
)

type CardAccess struct {
	RawData       []byte
	SecurityInfos *SecurityInfos
}

func NewCardAccess(data []byte) (*CardAccess, error) {
	var out CardAccess
	var err error

	if len(data) < 1 {
		return nil, nil
	}

	out.RawData = slices.Clone(data)
	out.SecurityInfos, err = DecodeSecurityInfos(out.RawData)
	if err != nil {
		return nil, err
	}

	return &out, nil
}
