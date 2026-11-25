package iso7816

import (
	"bytes"
	"log"

	"github.com/gmrtd/gmrtd/utils"
)

// MockTransceiverReqRsp is a C-APDU and the R-APDU a MockTransceiver returns for it.
type MockTransceiverReqRsp struct {
	req []byte
	rsp []byte
}

// MockTransceiver is a Transceiver for tests that answers each C-APDU with the R-APDU
// registered for it with AddReqRsp.
type MockTransceiver struct {
	reqRspArr []MockTransceiverReqRsp
}

var _ Transceiver = (*MockTransceiver)(nil)

// AddReqRsp registers the hex-encoded R-APDU rspHexStr as the response to the hex-encoded
// C-APDU reqHexStr.
func (transceiver *MockTransceiver) AddReqRsp(reqHexStr, rspHexStr string) {
	item := MockTransceiverReqRsp{}
	item.req = utils.HexToBytes(reqHexStr)
	item.rsp = utils.HexToBytes(rspHexStr)

	transceiver.reqRspArr = append(transceiver.reqRspArr, item)
}

// Transceive returns a copy of the first registered R-APDU whose C-APDU equals encodedData,
// ignoring the other arguments. It logs the C-APDU and returns an empty slice if none matches.
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
