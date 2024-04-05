package gmrtd

import "slices"

type CardSecurity struct {
	RawData       []byte
	SecurityInfos SecurityInfos
}

func NewCardSecurity(data []byte) *CardSecurity {
	if len(data) < 1 {
		return nil
	}

	var out *CardSecurity = new(CardSecurity)

	out.RawData = slices.Clone(data)
	out.SecurityInfos = *DecodeSecurityInfos(out.RawData)

	return out
}
