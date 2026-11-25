package tlv

// TlvNode is a decoded TLV element. It is implemented by TlvSimpleNode (primitive
// value), TlvConstructedNode (nested children) and TlvNilNode (the result of a lookup
// that found nothing), so lookups can be chained without nil checks.
type TlvNode interface {
	// IsValidNode reports whether the node holds real data; it is false only for
	// TlvNilNode.
	IsValidNode() bool
	// Tag returns the node's tag, or 0 for a TlvNilNode.
	Tag() TlvTag
	// Value returns the node's value bytes: the raw value of a simple node, the
	// re-encoded children of a constructed node, or an empty slice for a TlvNilNode.
	Value() []byte
	// NodeByTag returns the first direct child with the given tag. It never returns
	// nil: if there is no such child, or the node cannot have children, it returns a
	// TlvNilNode.
	NodeByTag(tag TlvTag) TlvNode
	// NodeByTagOccur returns the n-th (1-based) direct child with the given tag, or a
	// TlvNilNode if there is none. TlvConstructedNode panics if occurrence is less
	// than 1.
	NodeByTagOccur(tag TlvTag, occurrence int) TlvNode
	// Children returns the node's direct children; it is empty for simple and nil
	// nodes.
	Children() []TlvNode
	// Encode returns the node's BER-TLV encoding (tag, length and value), or nil for a
	// TlvNilNode.
	Encode() []byte
	// String returns an indented, human-readable dump of the node and its
	// descendants, intended for debugging.
	String() string
	stringWithIndent(indent int) string
}
