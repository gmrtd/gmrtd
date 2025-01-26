package tlv

import (
	"testing"
)

func TestNewConstructedNodeBadTagErr(t *testing.T) {
	defer func() { _ = recover() }()

	// attempt to create a ConstructedTag using a non-constructed tag
	_ = NewTlvConstructedNode(0x06)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}
