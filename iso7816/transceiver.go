package iso7816

// Transceiver sends a C-APDU to the chip and returns the raw R-APDU (data followed by the
// status word). The C-APDU is passed both as its fields and as encodedData, the complete
// encoded form, so an implementation can use whichever suits its NFC API. There is no error
// result: NfcSession treats a response of fewer than 2 bytes as an error.
type Transceiver interface {
	Transceive(cla int, ins int, p1 int, p2 int, data []byte, le int, encodedData []byte) []byte
}
