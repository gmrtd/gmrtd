package tlv

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestNodeByOccurBadOccurErr(t *testing.T) {
	defer func() { _ = recover() }()

	var nodes TlvNodes

	// force an error by using an invalid occur (i.e. 0)
	_ = nodes.NodeByTagOccur(0x12, 0)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestNodes(t *testing.T) {

	var nodes TlvNodes

	if len(nodes.Nodes()) != 0 {
		t.Errorf("Expected 0 children")
	}

	// NB nil-node should be silently ignored
	nodes.AddNode(NewTlvNilNode())

	if len(nodes.Nodes()) != 0 {
		t.Errorf("Expected 0 children")
	}

	nodes.AddNode(NewTlvSimpleNode(TlvTag(0x06), utils.HexToBytes("400601040102")))

	if len(nodes.Nodes()) != 1 {
		t.Errorf("Expected 1 child")
	}

	if !bytes.Equal(nodes.Encode(), utils.HexToBytes("0606400601040102")) {
		t.Errorf("Incorrect TLV encoding")
	}

	nodes.AddNode(NewTlvSimpleNode(TlvTag(0x06), utils.HexToBytes("400601040103")))

	if len(nodes.Nodes()) != 2 {
		t.Errorf("Expected 2 children")
	}

	if !bytes.Equal(nodes.Encode(), utils.HexToBytes("06064006010401020606400601040103")) {
		t.Errorf("Incorrect TLV encoding")
	}

	if !nodes.IsValidNode() {
		t.Errorf("Expected valid node")
	}
}
