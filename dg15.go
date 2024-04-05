package gmrtd

import "slices"

type DG15 struct {
	RawData []byte
}

func NewDG15(data []byte) *DG15 {
	if len(data) < 1 {
		return nil
	}

	var out *DG15 = new(DG15)

	out.RawData = slices.Clone(data)

	// TODO - parse the data

	return out
}
