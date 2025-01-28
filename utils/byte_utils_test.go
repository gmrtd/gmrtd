package utils

import (
	"bytes"
	"encoding/asn1"
	"strings"
	"testing"
)

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

func TestVerifyByteLengthErr(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	var bytes []byte = []byte{0x12, 0x34, 0x56}

	// NB trigger panic by specifying +1 length requirement
	VerifyByteLength(bytes, len(bytes)+1)

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

	bytes1 := GetBytesFromBuffer(buf, 2)
	bytes2 := GetBytesFromBuffer(buf, 3)
	bytes3 := GetBytesFromBuffer(buf, 2)
	bytes4 := GetBytesFromBuffer(buf, 1)

	if !bytes.Equal(bytes1, []byte{0x12, 0x34}) ||
		!bytes.Equal(bytes2, []byte{0x56, 0x78, 0x90}) ||
		!bytes.Equal(bytes3, []byte{0xab, 0xcd}) ||
		!bytes.Equal(bytes4, []byte{0xef}) {
		t.Errorf("GetBytesFromBuffer data differs to expected")
	}
}

func TestGetBytesFromBufferErr(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	var buf *bytes.Buffer = bytes.NewBuffer([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef})

	// NB throws exception as we request more bytes than are available
	_ = GetBytesFromBuffer(buf, 9)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")

}

func TestGetByteFromBuffer(t *testing.T) {
	var buf *bytes.Buffer = bytes.NewBuffer([]byte{0x12, 0x34, 0x56, 0x78})

	byte1 := GetByteFromBuffer(buf)
	byte2 := GetByteFromBuffer(buf)
	byte3 := GetByteFromBuffer(buf)
	byte4 := GetByteFromBuffer(buf)

	if (byte1 != 0x12) ||
		(byte2 != 0x34) ||
		(byte3 != 0x56) ||
		(byte4 != 0x78) {
		t.Errorf("GetByteFromBuffer data differs to expected")
	}
}

func TestIsImage(t *testing.T) {
	testCases := []struct {
		imageBytes []byte
		isImage    bool
	}{
		{
			// valid - has JPEG prefix: ffd8ffe000104a464946
			imageBytes: HexToBytes("ffd8ffe000104a4649460000000000000000000000000000000000000000"),
			isImage:    true,
		},
		{
			// valid - has JP2 Bitmap prefix: 0000000c6a5020200d0a
			imageBytes: HexToBytes("0000000c6a5020200d0a0000000000000000000000000000000000000000"),
			isImage:    true,
		},
		{
			// valid - has JP2 Code Stream Bitmap prefix: ff4fff51
			imageBytes: HexToBytes("ff4fff510000000000000000000000000000000000000000"),
			isImage:    true,
		},
		{
			// invalid image data - i.e. doesn't have a recognised image header
			imageBytes: HexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
			isImage:    false,
		},
	}
	for _, tc := range testCases {
		actIsImage := IsImage(tc.imageBytes)

		if actIsImage != tc.isImage {
			t.Errorf("IsImage result differs to expected (exp:%t, act:%t)", tc.isImage, actIsImage)
		}
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
