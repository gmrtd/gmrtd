package tlv

import (
	"bytes"
	"fmt"
	"strings"
)

type TlvConstructedNode struct {
	Tag      TlvTag
	Children TlvNodes
}

func (node TlvConstructedNode) IsValidNode() bool {
	return true
}

func (node TlvConstructedNode) GetTag() TlvTag {
	return node.Tag
}

func (node TlvConstructedNode) GetValue() []byte {
	return node.Children.Encode()
}

func (node TlvConstructedNode) GetNode(tag TlvTag) TlvNode {
	return node.Children.GetNode(tag)
}

func (node TlvConstructedNode) GetNodeByOccur(tag TlvTag, occurrence int) TlvNode {
	return node.Children.GetNodeByOccur(tag, occurrence)
}

func (node TlvConstructedNode) Encode() []byte {
	childData := node.Children.Encode()

	out := new(bytes.Buffer)
	out.Write(node.Tag.Encode())
	out.Write(TlvLength(len(childData)).Encode())
	out.Write(childData)

	return out.Bytes()
}

func (node TlvConstructedNode) stringWithIndent(indent int) string {
	var sb strings.Builder
	sb.WriteString(indentString(indent))
	sb.WriteString(fmt.Sprintf("%02x\n", node.Tag))
	sb.WriteString(node.Children.stringWithIndent(indent + 1))
	return sb.String()
}

func (node TlvConstructedNode) String() string {
	return node.stringWithIndent(0)
}

func (tlv *TlvConstructedNode) AddChild(child TlvNode) *TlvConstructedNode {
	tlv.Children.AddNode(child)
	return tlv
}

func NewTlvConstructedNode(tag TlvTag) *TlvConstructedNode {
	if !tag.IsConstructed() {
		panic(fmt.Sprintf("[NewTlvConstructedNode] Cannot create using a non-constructed tag (%02x)", tag))
	}

	return &TlvConstructedNode{Tag: tag}
}
