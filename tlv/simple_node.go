package tlv

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

type TlvSimpleNode struct {
	tag   TlvTag
	value []byte
}

func (node TlvSimpleNode) IsValidNode() bool {
	return true
}

func (node TlvSimpleNode) Tag() TlvTag {
	return node.tag
}

func (node TlvSimpleNode) Value() []byte {
	return node.value
}

func (node TlvSimpleNode) NodeByTag(_ TlvTag) TlvNode {
	// NB this node type cannot have children
	return NewTlvNilNode()
}

func (node TlvSimpleNode) NodeByTagOccur(_ TlvTag, _ int) TlvNode {
	// NB this node type cannot have children
	return NewTlvNilNode()
}

func (node TlvSimpleNode) Children() []TlvNode {
	return []TlvNode{}
}

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
		// special handling for ASN1 OIDs
		tmpOid := oid.DecodeAsn1objectId(node.value)
		tmpOidDesc := oid.OidDesc(tmpOid)
		sb.WriteString(fmt.Sprintf(" [%s: %s]", tmpOid.String(), tmpOidDesc))
	} else if utils.PrintableBytes(node.value) {
		// special handling for printable bytes
		sb.WriteString(fmt.Sprintf(" [%s]", string(node.value)))
	}
	sb.WriteString("\n")
	return sb.String()
}

func (node TlvSimpleNode) String() string {
	return node.stringWithIndent(0)
}

func NewTlvSimpleNode(tag TlvTag, value []byte) *TlvSimpleNode {
	return &TlvSimpleNode{tag: tag, value: value}
}
