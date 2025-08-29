package utils

import (
	"bytes"
	"encoding/asn1"
	"strings"
	"testing"
)

func TestTrimLeadingZeroBytes(t *testing.T) {
	testCases := []struct {
		data []byte
		exp  []byte
	}{
		{
			data: []byte{0, 0, 0, 0, 0, 1},
			exp:  []byte{1},
		},
		{
			data: []byte{0, 0, 0, 0, 0},
			exp:  []byte{},
		},
	}
	for _, tc := range testCases {
		act := TrimLeadingZeroBytes(tc.data)

		if !bytes.Equal(act, tc.exp) {
			t.Errorf("data mismatch (exp:%x, act:%x)", tc.exp, act)
		}
	}
}

func TestParseAsn1(t *testing.T) {
	testCases := []struct {
		data      []byte
		partial   bool
		out       interface{}
		expectErr bool
	}{
		{
			// SUCCESS
			data:      []byte{0x06, 0x03, 0x81, 0x34, 0x03}, // OID: 2.100.3
			partial:   false,
			out:       &asn1.ObjectIdentifier{},
			expectErr: false,
		},
		{
			// SUCCESS
			data:      []byte{0x06, 0x03, 0x81, 0x34, 0x03, 0xF1}, // OID: 2.100.3 (with extra data: 0xF1)
			partial:   true,
			out:       &asn1.ObjectIdentifier{},
			expectErr: false,
		},
		{
			// ERROR - unexpected partial read
			data:      []byte{0x06, 0x03, 0x81, 0x34, 0x03, 0xF1}, // OID: 2.100.3 (with UNEXPECTED extra data: 0xF1)
			partial:   false,
			out:       &asn1.ObjectIdentifier{},
			expectErr: true,
		},
		{
			// ERROR: no data to parse
			data:      []byte{},
			partial:   false,
			out:       &asn1.ObjectIdentifier{},
			expectErr: true,
		},
	}
	for _, tc := range testCases {
		err := ParseAsn1(tc.data, tc.partial, &tc.out)

		if tc.expectErr && err == nil {
			t.Errorf("Error expected")
		} else if !tc.expectErr && err != nil {
			t.Errorf("Error NOT expected")
		}
	}
}

func TestXorBytes(t *testing.T) {
	in1 := []byte{0x00, 0x00, 0xFF, 0xFF}
	in2 := []byte{0x00, 0xFF, 0x00, 0xFF}
	exp := []byte{0x00, 0xFF, 0xFF, 0x00}

	out := XorBytes(in1, in2)

	if !bytes.Equal(exp, out) {
		t.Errorf("XOR mismatch")
	}
}

func TestXorBytesErr(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	// NB cannot XOR when slices have different lengths
	in1 := []byte{0x00, 0x00, 0xFF, 0xFF}
	in2 := []byte{0x00, 0xFF, 0x00}

	_ = XorBytes(in1, in2)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestHexToBytes(t *testing.T) {
	testCases := []struct {
		inp string
		exp []byte
	}{
		{
			inp: "123456",
			exp: []byte{0x12, 0x34, 0x56},
		},
		{
			inp: "1234567890abcdef",
			exp: []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef},
		},
	}
	for _, tc := range testCases {
		act := HexToBytes(tc.inp)

		if !bytes.Equal(tc.exp, act) {
			t.Errorf("HexToBytes differs to expected (exp:%x, act:%x)", tc.exp, act)
		}
	}
}

func TestHexToBytesErr(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	// NB will fail due to 'ZZ'
	inp := "1234567890ABCDEFZZ1234"

	_ = HexToBytes(inp)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestBytesToHex(t *testing.T) {
	inp := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	exp := "0123456789ABCDEF"

	act := BytesToHex(inp)

	if !strings.EqualFold(act, exp) {
		t.Errorf("BytesToHex conversion error (exp:%s, act:%s)", exp, act)
	}
}

func TestPrintableBytes(t *testing.T) {
	testCases := []struct {
		data []byte
		exp  bool
	}{
		{
			data: []byte("This is a printable string!"),
			exp:  true,
		},
		{
			data: []byte("This is not \a printable string!"),
			exp:  false,
		},
		{
			data: []byte("This is not \a printable string! \xff"),
			exp:  false,
		},
	}
	for _, tc := range testCases {
		act := PrintableBytes(tc.data)

		if act != tc.exp {
			t.Errorf("PrintableBytes error (Exp:%t, Act:%t)", tc.exp, act)
		}
	}
}

func TestGetBytesFromBuffer(t *testing.T) {
	var buf *bytes.Buffer = bytes.NewBuffer([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef})

	expBytes := [][]byte{
		{0x12, 0x34},
		{0x56, 0x78, 0x90},
		{0xab, 0xcd},
		{0xef},
	}

	for i := range expBytes {
		expBytes := expBytes[i]

		actBytes, err := GetBytesFromBuffer(buf, len(expBytes))
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if !bytes.Equal(actBytes, expBytes) {
			t.Errorf("GetBytesFromBuffer data differs to expected (act:%x, exp:%x)", actBytes, expBytes)
		}
	}
}

func TestGetBytesFromBufferErr(t *testing.T) {
	var buf *bytes.Buffer = bytes.NewBuffer([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef})

	// NB error expected as we request more bytes than are available
	_, err := GetBytesFromBuffer(buf, 9)

	if err == nil {
		t.Errorf("error expected")
	}
}

func TestGetByteFromBuffer(t *testing.T) {
	var expBytes []byte = []byte{0x12, 0x34, 0x56, 0x78}
	var buf *bytes.Buffer = bytes.NewBuffer(expBytes)

	for i := range expBytes {
		expByte := expBytes[i]
		actByte, err := GetByteFromBuffer(buf)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if actByte != expByte {
			t.Errorf("GetByteFromBuffer data differs to expected (act:%x, exp:%x)", actByte, expByte)
		}
	}
}

func TestGetByteFromBufferErr(t *testing.T) {
	var buf *bytes.Buffer = bytes.NewBuffer([]byte{})

	// NB error expected as buffer contains no data
	_, err := GetByteFromBuffer(buf)
	if err == nil {
		t.Errorf("error expected")
	}
}

func TestBytesToInt(t *testing.T) {
	testCases := []struct {
		bytes []byte
		exp   int
	}{
		{
			bytes: nil,
			exp:   0,
		},
		{
			bytes: []byte{},
			exp:   0,
		},
		{
			bytes: []byte{0xff},
			exp:   255,
		},
		{
			bytes: []byte{0xff, 0xff},
			exp:   65535,
		},
		{
			bytes: []byte{0x1, 0x0, 0x1},
			exp:   65537,
		},
	}
	for _, tc := range testCases {
		act := BytesToInt(tc.bytes)

		if act != tc.exp {
			t.Errorf("bytesToInt error (Bytes:%x, Exp:%d, Act:%d)", tc.bytes, tc.exp, act)
		}
	}
}

func TestUInt16ToBytes(t *testing.T) {
	testCases := []struct {
		value    int
		expBytes []byte
	}{
		{
			value:    0x1234,
			expBytes: []byte{0x12, 0x34},
		},
	}
	for _, tc := range testCases {
		actBytes := UInt16ToBytes(uint16(tc.value))

		if !bytes.Equal(actBytes, tc.expBytes) {
			t.Errorf("Unexpected output (Exp:%x) (Act:%x)", tc.expBytes, actBytes)
		}
	}
}

func TestUInt32ToBytes(t *testing.T) {
	testCases := []struct {
		value    int
		expBytes []byte
	}{
		{
			value:    0x12345678,
			expBytes: []byte{0x12, 0x34, 0x56, 0x78},
		},
	}
	for _, tc := range testCases {
		actBytes := UInt32ToBytes(uint32(tc.value))

		if !bytes.Equal(actBytes, tc.expBytes) {
			t.Errorf("Unexpected output (Exp:%x) (Act:%x)", tc.expBytes, actBytes)
		}
	}
}

func TestUInt64ToBytes(t *testing.T) {
	testCases := []struct {
		value    int
		expBytes []byte
	}{
		{
			value:    0x1234567890abcdef,
			expBytes: []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef},
		},
	}
	for _, tc := range testCases {
		actBytes := UInt64ToBytes(uint64(tc.value))

		if !bytes.Equal(actBytes, tc.expBytes) {
			t.Errorf("Unexpected output (Exp:%x) (Act:%x)", tc.expBytes, actBytes)
		}
	}
}
