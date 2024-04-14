package gmrtd

import (
	"bytes"
	"log"
)

type MockTransceiverReqRsp struct {
	req []byte
	rsp []byte
}

type MockTransceiver struct {
	reqRspArr []MockTransceiverReqRsp
}

func (transceiver *MockTransceiver) AddReqRsp(reqHexStr string, rspHexStr string) {
	item := MockTransceiverReqRsp{}
	item.req = HexToBytes(reqHexStr)
	item.rsp = HexToBytes(rspHexStr)

	transceiver.reqRspArr = append(transceiver.reqRspArr, item)
}

func (transceiver *MockTransceiver) Transceive(capdu []byte) []byte {
	for i := range transceiver.reqRspArr {
		if bytes.Equal(transceiver.reqRspArr[i].req, capdu) {
			return transceiver.reqRspArr[i].rsp
		}
	}

	log.Panicf("Unable to match capdu with pre-registered data\n[REQ] %x", capdu)

	return nil
}

type StaticTransceiver struct {
	rapdu []byte
}

func (transceiver *StaticTransceiver) Transceive(capdu []byte) []byte {
	return transceiver.rapdu
}
