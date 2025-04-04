package iso7816

import (
	"testing"
)

func TestMockTransceiverBadReq(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	var transceiver MockTransceiver = MockTransceiver{}

	var cApdu *CApdu = NewCApdu(0x01, 0x02, 0x03, 0x04, []byte{0x05, 0x06}, 0x07)

	transceiver.Transceive(int(cApdu.cla), int(cApdu.ins), int(cApdu.p1), int(cApdu.p2), cApdu.data, cApdu.le, cApdu.Encode())

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}
