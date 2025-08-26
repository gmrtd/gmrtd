package iso7816

type StaticTransceiver struct {
	RApdu []byte
}

func (transceiver *StaticTransceiver) Transceive(cla int, ins int, p1 int, p2 int, data []byte, le int, encodedData []byte) []byte {
	return transceiver.RApdu
}
