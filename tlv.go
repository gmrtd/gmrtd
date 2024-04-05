package gmrtd

// TODO - add negative test cases... i.e. try to traverse tags that aren't present in the data

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
)

type TlvTag int

type TlvSimpleNode struct {
	Tag   TlvTag
	Value []byte
}

type TlvConstructedNode struct {
	Tag      TlvTag
	Children TlvNodes
}

type TlvNodes struct {
	Nodes []TlvNode
}

type TlvNilNode struct{}

func getIndentString(indent int) string {
	var sb strings.Builder
	for i := 0; i < indent; i++ {
		sb.WriteString("  ")
	}
	return sb.String()
}

func (node TlvNilNode) IsValidNode() bool {
	return false
}

func (node TlvNilNode) GetTag() TlvTag {
	return TlvTag(-1)
}

func (node TlvNilNode) GetValue() []byte {
	return nil
}

func (node TlvNilNode) GetNode(tag TlvTag) TlvNode {
	return NewTlvNilNode()
}

func (node TlvNilNode) GetNodeByOccur(tag TlvTag, occurrence int) TlvNode {
	return NewTlvNilNode()
}

func (node TlvNilNode) Encode() []byte {
	return nil
}

func (node TlvNilNode) stringWithIndent(indent int) string {
	return ""
}

func (node TlvNilNode) String() string {
	return ""
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

func (node TlvSimpleNode) GetNode(tag TlvTag) TlvNode {
	// NB this node type cannot have children
	return NewTlvNilNode()
}

func (node TlvSimpleNode) GetNodeByOccur(tag TlvTag, occurrence int) TlvNode {
	// NB this node type cannot have children
	return NewTlvNilNode()
}

func (node TlvSimpleNode) Encode() []byte {
	out := new(bytes.Buffer)
	out.Write(TlvEncodeTag(node.Tag))
	out.Write(TlvEncodeLength(len(node.Value)))
	out.Write(node.Value)
	return out.Bytes()
}

func (node TlvSimpleNode) stringWithIndent(indent int) string {
	var sb strings.Builder
	sb.WriteString(getIndentString(indent))
	sb.WriteString(fmt.Sprintf("%02x: %x", node.Tag, node.Value))
	if node.Tag == 0x06 {
		oid := DecodeAsn1objectId(node.Value) // TODO - should silently ignore if error?
		oidName := oid_lookup[oid]
		sb.WriteString(fmt.Sprintf(" [%s: %s]", oid, oidName))
	} else if PrintableBytes(node.Value) {
		sb.WriteString(fmt.Sprintf(" [\"%s\"]", string(node.Value)))
	}
	sb.WriteString("\n")
	return sb.String()
}

func (node TlvSimpleNode) String() string {
	return node.stringWithIndent(0)
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
	out.Write(TlvEncodeTag(node.Tag))
	out.Write(TlvEncodeLength(len(childData)))
	out.Write(childData)

	return out.Bytes()
}

func (node TlvConstructedNode) stringWithIndent(indent int) string {
	var sb strings.Builder
	sb.WriteString(getIndentString(indent))
	sb.WriteString(fmt.Sprintf("%02x\n", node.Tag))
	sb.WriteString(node.Children.stringWithIndent(indent + 1))
	return sb.String()
}

func (node TlvConstructedNode) String() string {
	return node.stringWithIndent(0)
}

func (tlv *TlvConstructedNode) AddChild(child TlvNode) {
	tlv.Children.AddNode(child)
}

func (node TlvNodes) IsValidNode() bool {
	return true
}

func (nodes TlvNodes) GetNode(tag TlvTag) TlvNode {
	return nodes.GetNodeByOccur(tag, 1)
}

// occurrence: 1-n
func (nodes TlvNodes) GetNodeByOccur(tag TlvTag, occurrence int) TlvNode {
	if occurrence < 1 {
		log.Panicf("occurrence must be 1..n")
	}

	curOccurrence := 0
	for _, child := range nodes.Nodes {
		if child.GetTag() == tag {
			curOccurrence++

			if occurrence == curOccurrence {
				return child
			}
		}
	}

	return NewTlvNilNode()
}

func (nodes TlvNodes) Encode() []byte {
	out := new(bytes.Buffer)

	for _, child := range nodes.Nodes {
		out.Write(child.Encode())
	}

	return out.Bytes() // TODO - should we be copying the bytes here? (others also).. e.g. slices.Clone()
}

func (nodes TlvNodes) stringWithIndent(indent int) string {
	var sb strings.Builder
	for _, child := range nodes.Nodes {
		sb.WriteString(child.stringWithIndent(indent))
	}
	return sb.String()
}

func (nodes TlvNodes) String() string {
	return nodes.stringWithIndent(0)
}

func (nodes *TlvNodes) AddNode(node TlvNode) {
	nodes.Nodes = append(nodes.Nodes, node)
}

type TlvNode interface {
	IsValidNode() bool
	GetTag() TlvTag
	GetValue() []byte
	GetNode(tag TlvTag) TlvNode
	GetNodeByOccur(tag TlvTag, occurrence int) TlvNode
	Encode() []byte
	String() string
	stringWithIndent(indent int) string
}

func NewTlvNilNode() *TlvNilNode {
	return &TlvNilNode{}
}

func NewTlvSimpleNode(tag TlvTag, value []byte) *TlvSimpleNode {
	return &TlvSimpleNode{Tag: tag, Value: value}
}

func NewTlvConstructedNode(tag TlvTag) *TlvConstructedNode {
	return &TlvConstructedNode{Tag: tag}
}

func NewTlvNodes() *TlvNodes {
	return &TlvNodes{}
}

func TlvDecode(data []byte) *TlvNodes {
	out := NewTlvNodes()

	buf := bytes.NewBuffer(data)

	for {
		if buf.Len() <= 0 {
			break
		}

		tag := TlvGetTag(buf)
		length := TlvGetLength(buf)

		if TlvIsConstructedTag(tag) {
			childData := getBytesFromBuffer(buf, length)
			children := TlvDecode(childData)
			node := NewTlvConstructedNode(tag)
			node.Children.Nodes = append(node.Children.Nodes, children.Nodes...)

			out.Nodes = append(out.Nodes, node)

		} else {
			value := getBytesFromBuffer(buf, length)
			node := NewTlvSimpleNode(tag, value)
			out.AddNode(node)
		}
	}

	return out
}

func TlvGetTag(buf *bytes.Buffer) TlvTag {
	b1 := getByteFromBuffer(buf)

	var tag int = int(b1)

	// special handling for multi-byte tags
	if (tag & 0x1f) == 0x1f {
		for {
			tmp := getByteFromBuffer(buf)

			tag <<= 8
			tag += int(tmp)

			if (tmp & 0x80) == 0 {
				break
			}

			if tag == 0x5fb0 {
				// TODO - workaround for DG13 on SG passport with bad tag (5FB0) which gets interpreted as (5FB08201)
				//		  and affects the parsing of the next tag.... double-check it's not our code
				break
			}
		}
	}

	return TlvTag(tag)
}

func TlvGetLength(buf *bytes.Buffer) (length int) {
	b1 := getByteFromBuffer(buf)

	if b1 <= 0x7f {
		// 1 byte: 0xxxxxxx (7 bit length)
		length = int(b1)
	} else if b1 >= 0x81 && b1 <= 0x84 {
		// 2 bytes: 10000001 xxxxxxxx (8 bit length)
		// 3 bytes: 10000010 xxxxxxxx xxxxxxxx (16 bit length)
		// 4 bytes: 10000011 xxxxxxxx xxxxxxxx xxxxxxxx (24 bit length)
		// 5 bytes: 10000100 xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx (32 bit length)
		byteLen := b1 - 0x80
		bytes := getBytesFromBuffer(buf, int(byteLen))
		uint32bytes := make([]byte, 4)
		copy(uint32bytes[4-byteLen:], bytes)
		length = int(binary.BigEndian.Uint32(uint32bytes))
	} else {
		log.Panicf("Unsupported length (b1:%02x) (remBytes:%x)", b1, buf.Bytes())
	}

	return
}

func TlvEncodeTag(tag TlvTag) []byte {
	var tmpBytes []byte = make([]byte, 8)
	binary.BigEndian.PutUint64(tmpBytes, uint64(tag))
	return bytes.TrimLeft(tmpBytes, "\x00")
}

func TlvEncodeLength(length int) []byte {
	out := make([]byte, 0)

	if length <= 127 {
		out = append(out, byte(length&0xff))
	} else if length <= 0xffffffff {
		var tmpBytes []byte = make([]byte, 4)
		binary.BigEndian.PutUint32(tmpBytes, uint32(length))
		significantBytes := bytes.TrimLeft(tmpBytes, "\x00")
		out = append(out, byte(0x80+len(significantBytes)))
		out = append(out, significantBytes...)
	} else {
		log.Panicf("Unsupported length (%d)", length)
	}

	return out
}

func TlvIsConstructedTag(tag TlvTag) bool {
	var tmp int = int(tag)

	// get the 1st byte of the tag
	for {
		if tmp <= 0xFF {
			break
		}
		tmp >>= 8
	}

	// constructed if bit 5 is set
	return (tmp & 0x20) == 0x20
}
