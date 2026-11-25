package iso7816

// StaticTransceiver is a Transceiver for tests that returns RApdu for every C-APDU.
type StaticTransceiver struct {
	RApdu []byte
}

var _ Transceiver = (*StaticTransceiver)(nil)

// Transceive returns RApdu (not a copy), ignoring its arguments.
func (transceiver *StaticTransceiver) Transceive(_ int, _ int, _ int, _ int, _ []byte, _ int, _ []byte) []byte {
	return transceiver.RApdu
}
