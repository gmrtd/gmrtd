package iso7816

type StaticTransceiver struct {
	RApdu []byte
}

func (transceiver *StaticTransceiver) Transceive(_ int, _ int, _ int, _ int, _ []byte, _ int, _ []byte) []byte {
	return transceiver.RApdu
}
