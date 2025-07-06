package iso7816

import (
	"testing"
)

func TestMockTransceiverBadReq(t *testing.T) {
	var transceiver MockTransceiver = MockTransceiver{}

	var cApdu *CApdu = NewCApdu(0x01, 0x02, 0x03, 0x04, []byte{0x05, 0x06}, 0x07)

	resp := transceiver.Transceive(int(cApdu.cla), int(cApdu.ins), int(cApdu.p1), int(cApdu.p2), cApdu.data, cApdu.le, cApdu.Encode())

	if len(resp) > 0 {
		t.Errorf("Unexpected response")
	}
}
