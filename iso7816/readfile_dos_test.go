package iso7816

import "testing"

// MockTransceiverHugeLength simulates evil chip sending TLV with gigantic length
type MockTransceiverHugeLength struct {
	iterationCount int
}

func (t *MockTransceiverHugeLength) Transceive(cla, ins, p1, p2 int, data []byte, le int, rapdu []byte) []byte {
	t.iterationCount++

	if ins == int(INS_SELECT) {
		// SELECT FILE - return success
		return []byte{0x90, 0x00}
	}

	if ins == int(INS_READ_BINARY) {
		offset := p1*256 + p2

		if offset == 0 {
			// Tag: 0x61 (DG1)
			// Length: 0x84 0xFF FF FF FF (4GB in long form)
			return append([]byte{
				0x61,                   // Tag
				0x84,                   // Long form length (4 bytes follow)
				0xFF, 0xFF, 0xFF, 0xFF, // Length = 4GB
			}, []byte{0x90, 0x00}...)
		} else {
			// Subsequent reads - just return some data to keep it going
			dummyData := make([]byte, le)
			for i := range dummyData {
				dummyData[i] = 0xAA
			}
			return append(dummyData, []byte{0x90, 0x00}...)
		}
	}

	return []byte{0x90, 0x00}
}

func TestReadFileDoSViaHugeLength(t *testing.T) {
	mockTrans := &MockTransceiverHugeLength{}
	nfc := NewNfcSession(mockTrans)

	nfc.MaxLe = 256

	_, err := nfc.ReadFile(0x0101) // DG1

	if err == nil {
		t.Errorf("Expected error")
	}
}
