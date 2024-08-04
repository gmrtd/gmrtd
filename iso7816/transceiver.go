package iso7816

type Transceiver interface {
	Transceive(capdu []byte) []byte
}
