package tlv

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

// TlvSimpleNode is a TLV element holding a raw value, with no children.
type TlvSimpleNode struct {
	tag   TlvTag
	value []byte
}

var _ TlvNode = (*TlvSimpleNode)(nil)

// IsValidNode always returns true.
func (node TlvSimpleNode) IsValidNode() bool {
	return true
}

// Tag returns the node's tag.
func (node TlvSimpleNode) Tag() TlvTag {
	return node.tag
}

// Value returns the node's value. The returned slice is not a copy.
func (node TlvSimpleNode) Value() []byte {
	return node.value
}

// NodeByTag always returns a TlvNilNode, as a simple node has no children.
func (node TlvSimpleNode) NodeByTag(_ TlvTag) TlvNode {
	// NB this node type cannot have children
	return NewTlvNilNode()
}

// NodeByTagOccur always returns a TlvNilNode, as a simple node has no children.
func (node TlvSimpleNode) NodeByTagOccur(_ TlvTag, _ int) TlvNode {
	// NB this node type cannot have children
	return NewTlvNilNode()
}

// Children always returns an empty slice.
func (node TlvSimpleNode) Children() []TlvNode {
	return []TlvNode{}
}

// Encode returns the node's BER-TLV encoding (tag, definite length and value).
func (node TlvSimpleNode) Encode() []byte {
	out := new(bytes.Buffer)
	out.Write(node.tag.Encode())
	out.Write(TlvLength(len(node.value)).Encode())
	out.Write(node.value)
	return out.Bytes()
}

func (node TlvSimpleNode) stringWithIndent(indent int) string {
	var sb strings.Builder
	sb.WriteString(indentString(indent))
	sb.WriteString(fmt.Sprintf("%02x: %x", node.tag, node.value))
	if node.tag == 0x06 {
		// special handling for ASN1 OIDs. node.value is untrusted TLV data straight off
		// the chip, and oid.DecodeAsn1objectId panics on malformed OID bytes (by design,
		// see oid.TestDecodeAsn1objectIdErr), so guard against that crashing what is only
		// a debug/display string.
		if desc, ok := tryDescribeOid(node.value); ok {
			sb.WriteString(fmt.Sprintf(" [%s]", desc))
		} else {
			sb.WriteString(" [invalid OID]")
		}
	} else if utils.PrintableBytes(node.value) {
		// special handling for printable bytes
		sb.WriteString(fmt.Sprintf(" [%s]", string(node.value)))
	}
	sb.WriteString("\n")
	return sb.String()
}

// String returns a human-readable line with the tag and hex value, followed by the
// decoded OID for tag 0x06 or the text for a printable value.
func (node TlvSimpleNode) String() string {
	return node.stringWithIndent(0)
}

// NewTlvSimpleNode returns a simple node with the given tag and value. The value is not
// copied, and the tag is not checked for being primitive.
func NewTlvSimpleNode(tag TlvTag, value []byte) *TlvSimpleNode {
	// NB we don't enforce Tag being !constructed
	return &TlvSimpleNode{tag: tag, value: value}
}

func tryDescribeOid(value []byte) (desc string, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()

	tmpOid := oid.DecodeAsn1objectId(value)

	return fmt.Sprintf("%s: %s", tmpOid.String(), oid.OidDesc(tmpOid)), true
}
