package gmrtd

import (
	"log"
	"slices"
)

type DG1 struct {
	RawData []byte
	Mrz     *MRZ
}

func NewDG1(data []byte) *DG1 {
	if len(data) < 1 {
		return nil
	}

	var out *DG1 = new(DG1)

	out.RawData = slices.Clone(data)

	tlv := TlvDecode(data)

	mrzBytes := tlv.GetNode(0x61).GetNode(0x5f1f).GetValue()
	if mrzBytes == nil {
		log.Panicf("MRZ Tag (61->5F1F) missing from DG1")
	}

	out.Mrz = MrzDecode(string(mrzBytes))

	return out
}
