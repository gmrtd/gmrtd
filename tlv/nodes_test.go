package tlv

import (
	"testing"
)

func TestGetNodeByOccurBadOccurErr(t *testing.T) {
	defer func() { _ = recover() }()

	var nodes TlvNodes

	// force an error by using an invalid occur (i.e. 0)
	_ = nodes.NodeByTagOccur(0x12, 0)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}
