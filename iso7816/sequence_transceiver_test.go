package iso7816

import (
	"bytes"
	"testing"
)

func TestSequenceTransceiver(t *testing.T) {
	var fallback MockTransceiver
	fallback.AddReqRsp("00A4000000", "6A82")

	transceiver := SequenceTransceiver{
		RApdus:   [][]byte{{0x90, 0x00}, {0x01, 0x90, 0x00}},
		Fallback: &fallback,
	}

	testCases := []struct {
		req    []byte
		expRsp []byte
	}{
		{req: []byte{0x00, 0xB0, 0x00, 0x00, 0x00}, expRsp: []byte{0x90, 0x00}},
		{req: []byte{0x00, 0xB0, 0x00, 0x00, 0x00}, expRsp: []byte{0x01, 0x90, 0x00}},
		{req: []byte{0x00, 0xA4, 0x00, 0x00, 0x00}, expRsp: []byte{0x6A, 0x82}}, // scripted R-APDUs exhausted, so falls back
		{req: []byte{0x00, 0xB0, 0x00, 0x00, 0x00}, expRsp: []byte{}},           // unknown to fallback
	}
	for i, tc := range testCases {
		if rsp := transceiver.Transceive(0, 0, 0, 0, nil, 0, tc.req); !bytes.Equal(rsp, tc.expRsp) {
			t.Errorf("[%d] rsp = %x, want %x", i, rsp, tc.expRsp)
		}
	}
}

func TestSequenceTransceiverNoFallback(t *testing.T) {
	transceiver := SequenceTransceiver{RApdus: [][]byte{{0x90, 0x00}}}

	_ = transceiver.Transceive(0, 0, 0, 0, nil, 0, nil)

	if rsp := transceiver.Transceive(0, 0, 0, 0, nil, 0, nil); len(rsp) != 0 {
		t.Errorf("rsp = %x, want empty", rsp)
	}
}

func TestSequenceTransceiverReturnsCopy(t *testing.T) {
	scripted := []byte{0x90, 0x00}
	transceiver := SequenceTransceiver{RApdus: [][]byte{scripted}}

	rsp := transceiver.Transceive(0, 0, 0, 0, nil, 0, nil)
	rsp[0] = 0xFF

	if scripted[0] != 0x90 {
		t.Errorf("scripted R-APDU was modified via the returned slice")
	}
}
