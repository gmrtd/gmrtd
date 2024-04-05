package gmrtd

import "slices"

type DG11 struct {
	RawData []byte
}

func NewDG11(data []byte) *DG11 {
	if len(data) < 1 {
		return nil
	}

	var out *DG11 = new(DG11)

	out.RawData = slices.Clone(data)

	// TODO - parse the data

	return out
}
