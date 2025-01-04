// Package TLV provides support for 'Tag-Length-Value' (TLV) formatted data.
package tlv

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strings"

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
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
	return node.stringWithIndent(0)
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
		// special handling for ASN1 OIDs
		oidStr := oid.DecodeAsn1objectId(node.Value).String()
		oidName := oid.OidLookup[oidStr]
		sb.WriteString(fmt.Sprintf(" [%s: %s]", oidStr, oidName))
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
		panic(fmt.Sprintf("[GetNodeByOccur] occurrence must be 1..n"))
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

	return bytes.Clone(out.Bytes())
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
	if !TlvIsConstructedTag(tag) {
		panic(fmt.Sprintf("[NewTlvConstructedNode] Cannot create using a non-constructed tag (%02x)", tag))
	}

	return &TlvConstructedNode{Tag: tag}
}

func NewTlvNodes() *TlvNodes {
	return &TlvNodes{}
}

// internal decode function - clients should use TlvDecode
func tlvDecode(data []byte) (nodes *TlvNodes, remainingData []byte) {
	nodes = NewTlvNodes()

	buf := bytes.NewBuffer(data)

	for {
		if buf.Len() <= 0 {
			break
		}

		tag := TlvGetTag(buf)
		length := TlvGetLength(buf)

		// special handling for indefinite-length mode end sentinel (i.e. 0x0000)
		if tag == 0 && length == 0 {
			remainingData = bytes.Clone(buf.Bytes())
			break
		}

		if TlvIsConstructedTag(tag) {
			var children *TlvNodes

			if length == -1 { // indefinite-length
				childData := bytes.Clone(buf.Bytes())
				buf = bytes.NewBuffer([]byte{})

				children, remainingData = tlvDecode(childData)

				node := NewTlvConstructedNode(tag)
				node.Children.Nodes = append(node.Children.Nodes, children.Nodes...)

				nodes.Nodes = append(nodes.Nodes, node)

				// we may or may not have remaining-data
				// if we do, then it needs to be processed as siblings for this node
				if len(remainingData) > 0 {
					buf = bytes.NewBuffer(remainingData)
					remainingData = nil
				}
			} else {
				childData := utils.GetBytesFromBuffer(buf, length)
				children, remainingData = tlvDecode(childData)
				if len(remainingData) > 0 {
					log.Panicf("Remaining-data not expected (%x)", remainingData)
				}
				node := NewTlvConstructedNode(tag)
				node.Children.Nodes = append(node.Children.Nodes, children.Nodes...)

				nodes.Nodes = append(nodes.Nodes, node)
			}
		} else {
			if length == -1 { // indefinite-length
				log.Panicf("Indefinite-length mode is only supported for constructed tags")
			} else {
				value := utils.GetBytesFromBuffer(buf, length)
				node := NewTlvSimpleNode(tag, value)
				nodes.AddNode(node)
			}
		}
	}

	return nodes, remainingData
}

func TlvDecode(data []byte) *TlvNodes {
	nodes, remainingData := tlvDecode(data)

	if len(remainingData) > 0 {
		log.Panicf("Unexpected remaining-data (%x)", remainingData)
	}

	return nodes
}

func TlvGetTag(buf *bytes.Buffer) TlvTag {
	b1 := utils.GetByteFromBuffer(buf)

	var tag int = int(b1)

	// special handling for multi-byte tags
	if (tag & 0x1f) == 0x1f {
		for {
			tmp := utils.GetByteFromBuffer(buf)

			tag <<= 8
			tag += int(tmp)

			if (tmp & 0x80) == 0 {
				break
			}
		}
	}

	return TlvTag(tag)
}

func TlvGetTags(buf *bytes.Buffer) []TlvTag {
	var out []TlvTag

	for {
		if buf.Len() <= 0 {
			break
		}
		out = append(out, TlvGetTag(buf))
	}

	return out
}

// decodes and returns the length
// NB returns -1 when 'indefinite-length' is indicated
func TlvGetLength(buf *bytes.Buffer) (length int) {
	b1 := utils.GetByteFromBuffer(buf)

	if b1 <= 0x7f {
		// 1 byte: 0xxxxxxx (7 bit length)
		length = int(b1)
	} else if b1 == 0x80 {
		// indefinite-length mode (0x80)
		// NB special-case where length is not specified and sequence is terminated by 0x0000
		//    - only valid for constructed tags
		length = -1
	} else if b1 >= 0x81 && b1 <= 0x84 {
		// 2 bytes: 10000001 xxxxxxxx (8 bit length)
		// 3 bytes: 10000010 xxxxxxxx xxxxxxxx (16 bit length)
		// 4 bytes: 10000011 xxxxxxxx xxxxxxxx xxxxxxxx (24 bit length)
		// 5 bytes: 10000100 xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx (32 bit length)
		byteLen := b1 - 0x80
		bytes := utils.GetBytesFromBuffer(buf, int(byteLen))
		uint32bytes := make([]byte, 4)
		copy(uint32bytes[4-byteLen:], bytes)
		length = int(binary.BigEndian.Uint32(uint32bytes))
	} else {
		panic(fmt.Sprintf("[TlvGetLength] Unsupported length (b1:%02x) (remBytes:%x)", b1, buf.Bytes()))
	}

	return length
}

func TlvEncodeTag(tag TlvTag) []byte {
	return bytes.TrimLeft(utils.UInt64ToBytes(uint64(tag)), "\x00")
}

// encodes the specified length
// NB special-handling for -1 as this indicates indefinite-length mode
func TlvEncodeLength(length int) []byte {
	out := make([]byte, 0)

	if length == -1 {
		out = append(out, byte(0x80))
	} else if length <= 127 {
		out = append(out, byte(length&0xff))
	} else if length <= 0xffffffff {
		significantBytes := bytes.TrimLeft(utils.UInt64ToBytes(uint64(length)), "\x00")
		out = append(out, byte(0x80+len(significantBytes)))
		out = append(out, significantBytes...)
	} else {
		panic(fmt.Sprintf("[TlvEncodeLength] Unsupported length (%d)", length))
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
