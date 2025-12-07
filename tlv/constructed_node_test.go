package tlv

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestNewConstructedNodeBadTagErr(t *testing.T) {
	defer func() { _ = recover() }()

	// attempt to create a ConstructedTag using a non-constructed tag
	_ = NewTlvConstructedNode(0x06)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestNewConstructedNode(t *testing.T) {
	// basic test:
	// - create constructed node (0x7C)
	// - add child node (0x01)
	// - add child node (0x02)
	// - verify that GeValue() works
	// - verify that String() returns something

	node := NewTlvConstructedNode(0x7C)

	node.AddChild(NewTlvSimpleNode(TlvTag(0x01), []byte{1, 2, 3, 4, 5}))
	node.AddChild(NewTlvSimpleNode(TlvTag(0x02), []byte{6, 7, 8, 9, 10}))

	value := node.Value()

	if !bytes.Equal(value, utils.HexToBytes("010501020304050205060708090a")) {
		t.Errorf("value mismatch")
	}

	nodeStr := node.String()

	// basic check to ensure we got something
	if len(nodeStr) < 1 {
		t.Errorf("expected string()")
	}
}
