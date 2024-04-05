package gmrtd

import "slices"

type CardAccess struct {
	RawData       []byte
	SecurityInfos SecurityInfos
}

func NewCardAccess(data []byte) *CardAccess {
	if len(data) < 1 {
		return nil
	}

	var out *CardAccess = new(CardAccess)

	out.RawData = slices.Clone(data)
	out.SecurityInfos = *DecodeSecurityInfos(out.RawData)

	return out
}
