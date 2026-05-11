package iso7816

import (
	"bytes"
	"log"

	"github.com/gmrtd/gmrtd/utils"
)

type MockTransceiverReqRsp struct {
	req []byte
	rsp []byte
}

type MockTransceiver struct {
	reqRspArr []MockTransceiverReqRsp
}

var _ Transceiver = (*MockTransceiver)(nil)

func (transceiver *MockTransceiver) AddReqRsp(reqHexStr, rspHexStr string) {
	item := MockTransceiverReqRsp{}
	item.req = utils.HexToBytes(reqHexStr)
	item.rsp = utils.HexToBytes(rspHexStr)

	transceiver.reqRspArr = append(transceiver.reqRspArr, item)
}

func (transceiver *MockTransceiver) Transceive(_ int, _ int, _ int, _ int, _ []byte, _ int, encodedData []byte) []byte {
	// NB we ignore the raw cApdu fields (cla,ins,p1,p2,data,l2) and just use encodedData (which is the same)
	for i := range transceiver.reqRspArr {
		if bytes.Equal(transceiver.reqRspArr[i].req, encodedData) {
			return bytes.Clone(transceiver.reqRspArr[i].rsp)
		}
	}

	log.Printf("unknown CApdu: %x\n", encodedData)

	// if we got here then we couldn't match the C-APDU
	return []byte{}
}
