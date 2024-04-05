package gmrtd

type Transceiver interface {
	Transceive(capdu []byte) []byte
}
