package tlv

// TlvNilNode is the TlvNode returned when a lookup finds nothing. It is not a valid
// node, has tag 0 and no value or children, and lookups on it return another
// TlvNilNode.
type TlvNilNode struct{}

var _ TlvNode = (*TlvNilNode)(nil)

// IsValidNode always returns false.
func (node TlvNilNode) IsValidNode() bool {
	return false
}

// Tag always returns 0.
func (node TlvNilNode) Tag() TlvTag {
	return TlvTag(0)
}

// Value always returns an empty slice.
func (node TlvNilNode) Value() []byte {
	return []byte{}
}

// NodeByTag always returns a TlvNilNode.
func (node TlvNilNode) NodeByTag(_ TlvTag) TlvNode {
	return NewTlvNilNode()
}

// NodeByTagOccur always returns a TlvNilNode, whatever the occurrence.
func (node TlvNilNode) NodeByTagOccur(_ TlvTag, _ int) TlvNode {
	return NewTlvNilNode()
}

// Children always returns an empty slice.
func (node TlvNilNode) Children() []TlvNode {
	return []TlvNode{}
}

// Encode always returns nil.
func (node TlvNilNode) Encode() []byte {
	return nil
}

func (node TlvNilNode) stringWithIndent(_ int) string {
	return ""
}

// String always returns an empty string.
func (node TlvNilNode) String() string {
	return node.stringWithIndent(0)
}

// NewTlvNilNode returns a new TlvNilNode.
func NewTlvNilNode() *TlvNilNode {
	return &TlvNilNode{}
}
