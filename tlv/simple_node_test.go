package tlv

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestNewSimpleNode(t *testing.T) {
	var node TlvNode

	node = NewTlvSimpleNode(TlvTag(0x06), utils.HexToBytes("400601040102"))

	if len(node.Children()) != 0 {
		t.Errorf("Expected 0 children")
	}

	if len(node.Children()) != 0 {
		t.Errorf("Expected 0 children")
	}

	if !node.IsValidNode() {
		t.Errorf("Expected valid node")
	}

	if node.Tag() != TlvTag(0x06) {
		t.Errorf("Incorrect Tag")
	}

	if !bytes.Equal(node.Value(), utils.HexToBytes("400601040102")) {
		t.Errorf("Incorrect Value")
	}

	if !bytes.Equal(node.Encode(), utils.HexToBytes("0606400601040102")) {
		t.Errorf("Incorrect TLV encoding")
	}

	nodeStr := node.String()

	// basic check to ensure we got something
	if len(nodeStr) < 1 {
		t.Errorf("expected string()")
	}
}

func TestSimpleNodeStringInvalidOid(t *testing.T) {
	// oid.DecodeAsn1objectId panics on malformed OID bytes (empty being the simplest
	// case); String() must recover and render a placeholder instead of panicking.
	node := NewTlvSimpleNode(TlvTag(0x06), []byte{})

	nodeStr := node.String()

	if !strings.Contains(nodeStr, "invalid OID") {
		t.Errorf("expected 'invalid OID' placeholder in string, got: %s", nodeStr)
	}
}
