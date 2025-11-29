package tlv

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

type TlvSimpleNode struct {
	Tag   TlvTag
	Value []byte
}

func (node TlvSimpleNode) IsValidNode() bool {
	return true
}

func (node TlvSimpleNode) GetTag() TlvTag {
	return node.Tag
}

func (node TlvSimpleNode) GetValue() []byte {
	return node.Value
}

func (node TlvSimpleNode) GetNode(_ TlvTag) TlvNode {
	// NB this node type cannot have children
	return NewTlvNilNode()
}

func (node TlvSimpleNode) GetNodeByOccur(_ TlvTag, _ int) TlvNode {
	// NB this node type cannot have children
	return NewTlvNilNode()
}

func (node TlvSimpleNode) Encode() []byte {
	out := new(bytes.Buffer)
	out.Write(node.Tag.Encode())
	out.Write(TlvLength(len(node.Value)).Encode())
	out.Write(node.Value)
	return out.Bytes()
}

func (node TlvSimpleNode) stringWithIndent(indent int) string {
	var sb strings.Builder
	sb.WriteString(indentString(indent))
	sb.WriteString(fmt.Sprintf("%02x: %x", node.Tag, node.Value))
	if node.Tag == 0x06 {
		// special handling for ASN1 OIDs
		tmpOid := oid.DecodeAsn1objectId(node.Value)
		tmpOidDesc := oid.OidDesc(tmpOid)
		sb.WriteString(fmt.Sprintf(" [%s: %s]", tmpOid.String(), tmpOidDesc))
	} else if utils.PrintableBytes(node.Value) {
		// special handling for printable bytes
		sb.WriteString(fmt.Sprintf(" [%s]", string(node.Value)))
	}
	sb.WriteString("\n")
	return sb.String()
}

func (node TlvSimpleNode) String() string {
	return node.stringWithIndent(0)
}

func NewTlvSimpleNode(tag TlvTag, value []byte) *TlvSimpleNode {
	return &TlvSimpleNode{Tag: tag, Value: value}
}
