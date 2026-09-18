package tlv

import (
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func FuzzDecode(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(utils.HexToBytes("61085f1f050123456789"))
	f.Add(utils.HexToBytes("61805f1f0501234567890000")) // indefinite length
	f.Add(utils.HexToBytes("61095f1f050123456789"))     // less data than expected
	f.Add(utils.HexToBytes("61"))                       // tag only, missing length/data
	f.Add(utils.HexToBytes("61085f1f8001234567890000")) // indefinite length not allowed on non-composite
	f.Add(utils.HexToBytes("0184FFFFFFFF"))             // huge declared length, no value bytes (see TestDecodeHugeLengthDoesNotOverAllocate)

	f.Fuzz(func(t *testing.T, data []byte) {
		nodes, err := Decode(data)
		if err != nil {
			return
		}
		if nodes == nil {
			t.Fatalf("Decode returned nil nodes with nil error")
		}

		// roundtrip invariant: a successfully decoded tree must re-encode without panicking
		_ = nodes.Encode()
	})
}
