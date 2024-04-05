package gmrtd

import "slices"

type DG12 struct {
	RawData []byte
}

func NewDG12(data []byte) *DG12 {
	if len(data) < 1 {
		return nil
	}

	var out *DG12 = new(DG12)

	out.RawData = slices.Clone(data)

	// TODO - parse the data

	return out
}
