package gmrtd

import (
	"log"
	"slices"
)

type DG14 struct {
	RawData  []byte // TODO - add to test cases (for all other DGs also)
	secInfos *SecurityInfos
}

func NewDG14(data []byte) *DG14 {
	if len(data) < 1 {
		return nil
	}

	var out *DG14 = new(DG14)

	out.RawData = slices.Clone(data)

	tlv := TlvDecode(data)

	secInfosBytes := tlv.GetNode(0x6e).GetValue()
	if secInfosBytes == nil {
		log.Panicf("SecInfosTag (6E) missing from DG14")
	}

	out.secInfos = DecodeSecurityInfos(secInfosBytes)

	return out
}
