package tlv

import (
	"bytes"
	"fmt"
	"strings"
)

type TlvConstructedNode struct {
	tag      TlvTag
	children TlvNodes
}

func (node TlvConstructedNode) IsValidNode() bool {
	return true
}

func (node TlvConstructedNode) Tag() TlvTag {
	return node.tag
}

func (node TlvConstructedNode) Value() []byte {
	return node.children.Encode()
}

func (node TlvConstructedNode) NodeByTag(tag TlvTag) TlvNode {
	return node.children.NodeByTag(tag)
}

func (node TlvConstructedNode) NodeByTagOccur(tag TlvTag, occurrence int) TlvNode {
	return node.children.NodeByTagOccur(tag, occurrence)
}

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

func (node TlvConstructedNode) String() string {
	return node.stringWithIndent(0)
}

func (tlv *TlvConstructedNode) AddChild(child TlvNode) *TlvConstructedNode {
	tlv.children.AddNode(child)
	return tlv
}

func NewTlvConstructedNode(tag TlvTag) *TlvConstructedNode {
	if !tag.IsConstructed() {
		panic(fmt.Sprintf("[NewTlvConstructedNode] Cannot create using a non-constructed tag (%02x)", tag))
	}

	return &TlvConstructedNode{tag: tag}
}
