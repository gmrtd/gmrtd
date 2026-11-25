package tlv

import (
	"bytes"
	"strings"
)

// TlvNodes is an ordered list of sibling TLV nodes, as returned by Decode for the
// top level of the input. It is not itself a TlvNode.
type TlvNodes struct {
	nodes []TlvNode
}

// IsValidNode always returns true.
func (node TlvNodes) IsValidNode() bool {
	return true
}

// NodeByTag returns the first node in the list with the given tag, or a TlvNilNode if
// there is none. Only the list itself is searched, not the nodes' children.
func (nodes TlvNodes) NodeByTag(tag TlvTag) TlvNode {
	return nodes.NodeByTagOccur(tag, 1)
}

// NodeByTagOccur returns the n-th (1-based) node in the list with the given tag, or a
// TlvNilNode if there is none. It panics if occurrence is less than 1.
//
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

// Nodes returns the nodes in the list. The returned slice is not a copy.
func (nodes TlvNodes) Nodes() []TlvNode {
	return nodes.nodes
}

// Encode returns the concatenated BER-TLV encoding of the nodes in the list.
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

// String returns an indented, human-readable dump of the nodes, intended for debugging.
func (nodes TlvNodes) String() string {
	return nodes.stringWithIndent(0)
}

// AddNode appends node to the list. Invalid nodes (such as a TlvNilNode) are silently
// ignored.
func (nodes *TlvNodes) AddNode(node TlvNode) {
	// silently ignore invalid nodes (e.g. nil-node)
	if !node.IsValidNode() {
		return
	}

	nodes.nodes = append(nodes.nodes, node)
}

// AddNodes appends each valid node in nodesToAdd to the list.
func (nodes *TlvNodes) AddNodes(nodesToAdd TlvNodes) {
	for _, node := range nodesToAdd.Nodes() {
		nodes.AddNode(node)
	}
}
