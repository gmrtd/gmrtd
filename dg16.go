package gmrtd

import "slices"

type DG16 struct {
	RawData []byte
}

func NewDG16(data []byte) *DG16 {
	if len(data) < 1 {
		return nil
	}

	var out *DG16 = new(DG16)

	out.RawData = slices.Clone(data)

	// TODO - parse the data

	return out
}
