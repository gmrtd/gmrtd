package tlv

import (
	"bytes"
	"strings"
)

type TlvNodes struct {
	Nodes []TlvNode
}

func (node TlvNodes) IsValidNode() bool {
	return true
}

func (nodes TlvNodes) NodeByTag(tag TlvTag) TlvNode {
	return nodes.NodeByTagOccur(tag, 1)
}

// occurrence: 1-n
func (nodes TlvNodes) NodeByTagOccur(tag TlvTag, occurrence int) TlvNode {
	if occurrence < 1 {
		panic("[NodeByTagOccur] occurrence must be 1..n")
	}

	curOccurrence := 0
	for _, child := range nodes.Nodes {
		if child.Tag() == tag {
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

func NewTlvNodes() *TlvNodes {
	return &TlvNodes{}
}
