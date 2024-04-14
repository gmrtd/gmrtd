package gmrtd

import "slices"

type CardSecurity struct {
	RawData       []byte
	SecurityInfos *SecurityInfos
}

func NewCardSecurity(data []byte) (out *CardSecurity, err error) {
	if len(data) < 1 {
		return nil, nil
	}

	out = new(CardSecurity)

	out.RawData = slices.Clone(data)
	if out.SecurityInfos, err = DecodeSecurityInfos(out.RawData); err != nil {
		return nil, err
	}

	return out, nil
}
