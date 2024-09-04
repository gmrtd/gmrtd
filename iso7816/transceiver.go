package iso7816

type Transceiver interface {
	Transceive(cla int, ins int, p1 int, p2 int, data []byte, le int, encodedData []byte) []byte
}
