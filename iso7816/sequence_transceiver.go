package iso7816

import "bytes"

// SequenceTransceiver returns its scripted R-APDUs in order, regardless of the C-APDU sent, then
// defers to Fallback (if set) once they run out. Unlike MockTransceiver it doesn't depend on the
// exact C-APDU, so a test can substitute any chip response (e.g. fuzzed bytes) mid-session even
// though that changes every C-APDU derived from it.
type SequenceTransceiver struct {
	RApdus   [][]byte
	Fallback Transceiver

	idx int
}

var _ Transceiver = (*SequenceTransceiver)(nil)

func (transceiver *SequenceTransceiver) Transceive(cla int, ins int, p1 int, p2 int, data []byte, le int, encodedData []byte) []byte {
	if transceiver.idx < len(transceiver.RApdus) {
		rApdu := transceiver.RApdus[transceiver.idx]
		transceiver.idx++
		return bytes.Clone(rApdu)
	}

	if transceiver.Fallback != nil {
		return transceiver.Fallback.Transceive(cla, ins, p1, p2, data, le, encodedData)
	}

	return []byte{}
}
