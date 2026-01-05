package tlv

import (
	"bytes"
	"strings"
)

type TlvNodes struct {
	nodes []TlvNode
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
	for _, child := range nodes.nodes {
		if child.Tag() == tag {
			curOccurrence++

			if occurrence == curOccurrence {
				return child
			}
		}
	}

	return NewTlvNilNode()
}

func (nodes TlvNodes) Nodes() []TlvNode {
	return nodes.nodes
}

func (nodes TlvNodes) Encode() []byte {
	out := new(bytes.Buffer)

	for _, child := range nodes.nodes {
		out.Write(child.Encode())
	}

	return bytes.Clone(out.Bytes())
}

// TODO - may want this to return a standard string... once we have a better way of generating formatted TLV (will need to update other instances also)
//
//	e.g. {tag:0x06, children:{...}}
func (nodes TlvNodes) stringWithIndent(indent int) string {
	var sb strings.Builder
	for _, child := range nodes.nodes {
		sb.WriteString(child.stringWithIndent(indent))
	}
	return sb.String()
}

func (nodes TlvNodes) String() string {
	return nodes.stringWithIndent(0)
}

func (nodes *TlvNodes) AddNode(node TlvNode) {
	// silently ignore invalid nodes (e.g. nil-node)
	if !node.IsValidNode() {
		return
	}

	nodes.nodes = append(nodes.nodes, node)
}

func (nodes *TlvNodes) AddNodes(nodesToAdd TlvNodes) {
	for _, node := range nodesToAdd.Nodes() {
		nodes.AddNode(node)
	}
}
