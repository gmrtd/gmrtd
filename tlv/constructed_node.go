package tlv

import (
	"bytes"
	"fmt"
	"strings"
)

// TlvConstructedNode is a TLV element with a constructed tag, whose value is a sequence
// of child nodes.
type TlvConstructedNode struct {
	tag      TlvTag
	children TlvNodes
}

var _ TlvNode = (*TlvConstructedNode)(nil)

// IsValidNode always returns true.
func (node TlvConstructedNode) IsValidNode() bool {
	return true
}

// Tag returns the node's tag.
func (node TlvConstructedNode) Tag() TlvTag {
	return node.tag
}

// Value returns the concatenated encoding of the node's children.
func (node TlvConstructedNode) Value() []byte {
	return node.children.Encode()
}

// NodeByTag returns the first direct child with the given tag, or a TlvNilNode if
// there is none. Only direct children are searched.
func (node TlvConstructedNode) NodeByTag(tag TlvTag) TlvNode {
	return node.children.NodeByTag(tag)
}

// NodeByTagOccur returns the n-th (1-based) direct child with the given tag, or a
// TlvNilNode if there is none. It panics if occurrence is less than 1.
func (node TlvConstructedNode) NodeByTagOccur(tag TlvTag, occurrence int) TlvNode {
	return node.children.NodeByTagOccur(tag, occurrence)
}

// Children returns the node's direct children in order.
func (node TlvConstructedNode) Children() []TlvNode {
	return node.children.Nodes()
}

// Encode returns the node's BER-TLV encoding, always using a definite length even if
// the node was decoded from indefinite-length input.
func (node TlvConstructedNode) Encode() []byte {
	childData := node.children.Encode()

	out := new(bytes.Buffer)
	out.Write(node.tag.Encode())
	out.Write(TlvLength(len(childData)).Encode())
	out.Write(childData)

	return out.Bytes()
}

func (node TlvConstructedNode) stringWithIndent(indent int) string {
	var sb strings.Builder
	sb.WriteString(indentString(indent))
	sb.WriteString(fmt.Sprintf("%02x\n", node.tag))
	sb.WriteString(node.children.stringWithIndent(indent + 1))
	return sb.String()
}

// String returns an indented, human-readable dump of the node and its children.
func (node TlvConstructedNode) String() string {
	return node.stringWithIndent(0)
}

// AddChild appends child to the node and returns the node, so calls can be chained.
// Invalid children (such as a TlvNilNode) are silently ignored.
func (tlv *TlvConstructedNode) AddChild(child TlvNode) *TlvConstructedNode {
	tlv.children.AddNode(child)
	return tlv
}

// NewTlvConstructedNode returns an empty constructed node with the given tag. It panics
// if tag is not a constructed tag; it is intended for building TLV data in code, not
// for tags taken from untrusted input.
func NewTlvConstructedNode(tag TlvTag) *TlvConstructedNode {
	if !tag.IsConstructed() {
		panic(fmt.Sprintf("[NewTlvConstructedNode] Cannot create using a non-constructed tag (%02x)", tag))
	}

	return &TlvConstructedNode{tag: tag}
}
