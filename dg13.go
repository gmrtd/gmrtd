package gmrtd

import "slices"

type DG13 struct {
	RawData []byte
}

func NewDG13(data []byte) *DG13 {
	if len(data) < 1 {
		return nil
	}

	var out *DG13 = new(DG13)

	out.RawData = slices.Clone(data)

	// TODO - parse the data

	return out
}
