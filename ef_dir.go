package gmrtd

import "slices"

type EFDIR struct {
	RawData []byte
}

// TODO - should we give others the EF prefix also?.. or move to a sub-module?

func NewEFDIR(data []byte) *EFDIR {
	if len(data) < 1 {
		return nil
	}

	var out *EFDIR = new(EFDIR)

	out.RawData = slices.Clone(data)

	// TODO - parse the data

	return out
}
