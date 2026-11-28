package tlv

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestDecode(t *testing.T) {
	inp := utils.HexToBytes("61085f1f050123456789")
	out, err := Decode(inp)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	act := out.NodeByTag(0x61).NodeByTag(0x5f1f).Value()

	exp := utils.HexToBytes("0123456789")

	if !bytes.Equal(exp, act) {
		t.Errorf("TLV Decode error (Exp:%x, Act:%x)", exp, act)
	}
}

func TestDecodeIndefinteLength(t *testing.T) {
	inp := utils.HexToBytes("61805f1f0501234567890000")
	out, err := Decode(inp)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	act := out.NodeByTag(0x61).NodeByTag(0x5f1f).Value()

	exp := utils.HexToBytes("0123456789")

	if !bytes.Equal(exp, act) {
		t.Errorf("TLV Decode error (Exp:%x, Act:%x)", exp, act)
	}
}

func TestDecodeEndOfContentsBoundaries(t *testing.T) {
	const first, end, sibling = "0101AA", "0000", "0201BB"
	for _, tc := range []struct{ name, input string }{
		{"trailing top-level data", first + end + sibling},
		{"end-of-contents inside definite-length container", "6108" + first + end + sibling},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodes, err := Decode(utils.HexToBytes(tc.input))
			if err == nil || nodes != nil {
				t.Fatalf("expected trailing-data error and no tree, got tree present=%t, err=%v", nodes != nil, err)
			}
		})
	}
	nodes, err := Decode(utils.HexToBytes("6180" + first + end + sibling))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := nodes.Encode(), utils.HexToBytes("6103"+first+sibling); !bytes.Equal(got, want) {
		t.Fatalf("decoded tree encodes as %x, want %x", got, want)
	}
}

func TestDecodeErrors(t *testing.T) {
	testCases := []struct {
		data []byte
	}{
		{
			// less data than expected
			data: utils.HexToBytes("61095f1f050123456789"),
			//						  || should be 08
		},
		{
			// less data than expected.. normal node not composite
			data: utils.HexToBytes("61085f1f060123456789"),
			//						  		|| should be 05
		},
		{
			// tag but no length/data
			data: utils.HexToBytes("61"),
			//						|| tag only, missing length/data
		},
		{
			// indefinite length with normal tag (but only allowed for composites)
			data: utils.HexToBytes("61085f1f8001234567890000"),
			//						  		|| indefinite-length not allowed unless composite tag
		},
		{
			// indefinite length, but contains a normal node with less data than expected
			data: utils.HexToBytes("61805f1f110000"),
			//                              || less data than expected (x11, but really x00)
		},
	}
	for _, tc := range testCases {
		_, err := Decode(tc.data)
		if err == nil {
			t.Errorf("Expected error")
		}
	}
}

func TestDecodeExceedsMaxDepth(t *testing.T) {
	// Build a deeply nested constructed TLV that exceeds maxDecodeDepth.
	// Each level: tag 0x61 (constructed) + indefinite length (0x80) ... terminated by 0x0000
	depth := maxDecodeDepth + 1
	var buf []byte
	for i := 0; i < depth; i++ {
		buf = append(buf, 0x61, 0x80) // constructed tag + indefinite length
	}
	// innermost primitive
	buf = append(buf, 0x01, 0x01, 0xFF)
	// close all indefinite-length levels
	for i := 0; i < depth; i++ {
		buf = append(buf, 0x00, 0x00)
	}

	_, err := Decode(buf)
	if err == nil {
		t.Errorf("Expected depth-exceeded error")
	}
}

func TestDecodeExceedsMaxNodes(t *testing.T) {
	// Build a flat TLV with more than maxDecodeNodes primitive nodes.
	count := maxDecodeNodes + 1
	buf := make([]byte, 0, count*3)
	for i := 0; i < count; i++ {
		buf = append(buf, 0x01, 0x01, 0xFF) // tag=0x01, len=1, value=0xFF
	}

	_, err := Decode(buf)
	if err == nil {
		t.Errorf("Expected node-count-exceeded error")
	}
}

func TestDecodeNodeLimitAcrossSiblings(t *testing.T) {
	const groups = 4
	const leavesPerGroup = maxDecodeNodes/groups - 1 // The constructed parent also counts.
	if groups*(leavesPerGroup+1) != maxDecodeNodes {
		t.Fatalf("%d groups of %d nodes do not reach the limit of %d exactly", groups, leavesPerGroup+1, maxDecodeNodes)
	}
	group := NewTlvConstructedNode(0x61)
	leaf := NewTlvSimpleNode(0x01, nil)
	for range leavesPerGroup {
		group.AddChild(leaf)
	}
	siblings := bytes.Repeat(group.Encode(), groups-1)
	nodes, err := Decode(append(siblings, group.Encode()...))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes.Nodes()) != groups {
		t.Fatalf("decoded %d groups, want %d", len(nodes.Nodes()), groups)
	}
	for i, node := range nodes.Nodes() {
		if got := len(node.Children()); got != leavesPerGroup {
			t.Fatalf("group %d has %d children, want %d", i, got, leavesPerGroup)
		}
	}
	group.AddChild(leaf)
	nodes, err = Decode(append(siblings, group.Encode()...))
	if err == nil || !strings.Contains(err.Error(), "maximum node count") || nodes != nil {
		t.Fatalf("expected a node-count error and no partial tree, got nodes present=%t, err=%v", nodes != nil, err)
	}
}

func TestDecodeHugeLengthDoesNotOverAllocate(t *testing.T) {
	// Evil TLV: tag 0x01, long-form length claiming ~4GB, but no actual value bytes.
	// Found by fuzzing (FuzzDecode): before the fix, the declared length was passed
	// straight to make([]byte, length) without checking how much data was actually
	// available, so a ~7 byte input could force a multi-GB allocation attempt.
	inp := utils.HexToBytes("0184FFFFFFFF")

	_, err := Decode(inp)
	if err == nil {
		t.Errorf("Expected error for length exceeding available data")
	}
}

func TestMustDecodeErrors(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	// less data than expected
	_ = MustDecode(utils.HexToBytes("61095f1f050123456789"))
	//						           || should be 08

	t.Errorf("should have panicked")
}
