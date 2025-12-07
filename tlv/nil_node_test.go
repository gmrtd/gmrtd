package tlv

import (
	"testing"
)

func TestNilNode(t *testing.T) {
	node := NewTlvNilNode()

	if node.Tag() != -1 {
		t.Errorf("Expected tag: -1")
	}

	if len(node.Value()) > 0 {
		t.Errorf("Expected empty value")
	}

	if len(node.Encode()) > 0 {
		t.Errorf("Expected empty (encoded) value")
	}

	if len(node.String()) > 0 {
		t.Errorf("Expected empty String()")
	}
}
