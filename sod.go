package gmrtd

import "slices"

// TODO - 2 versions of SOD... v1 (preferred) and legacy format v0

type SOD struct {
	RawData []byte
	nodes   *TlvNodes
}

func NewSOD(data []byte) *SOD {
	if len(data) < 1 {
		return nil
	}

	var out *SOD = new(SOD)

	out.RawData = slices.Clone(data)

	// TODO (HACK) - just decoding, not actually testing anything

	out.nodes = TlvDecode(data)

	//slog.Debug("SOD","tlv",out.nodes)

	return out
}
