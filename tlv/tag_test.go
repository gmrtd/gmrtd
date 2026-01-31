package tlv

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestParseTag(t *testing.T) {
	testCases := []struct {
		inpBytes []byte
		expErr   bool
		expTag   TlvTag
	}{
		{
			inpBytes: []byte{0},
			expErr:   false,
			expTag:   0,
		},
		{
			inpBytes: []byte{0x1f, 0x80, 0x80, 0x00},
			expErr:   false,
			expTag:   0x1f808000,
		},
		{
			inpBytes: []byte{0xff, 0xff, 0xff, 0x7f},
			expErr:   false,
			expTag:   0xffffff7f,
		},
		{
			// error: tag exceeds 4 bytes
			inpBytes: []byte{0x1f, 0x80, 0x80, 0x80, 0x00},
			expErr:   true,
		},
		{
			// error: tag exceeds 4 bytes
			inpBytes: []byte{0x5F, 0xD2, 0xD2, 0xD2, 0xD2, 0xD2, 0xD2, 0xD2, 0x41},
			expErr:   true,
		},
	}
	for _, tc := range testCases {
		actTag, err := ParseTag(bytes.NewBuffer(tc.inpBytes))

		if tc.expErr {
			if err == nil {
				t.Errorf("Error expected")
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error: %s", err)
			} else if tc.expTag != actTag {
				t.Errorf("Tag differs to expected (act:%1d, exp:%1d)", actTag, tc.expTag)
			}
		}
	}
}

func TestGetTags(t *testing.T) {
	testCases := []struct {
		inp    []byte
		expOut []TlvTag
	}{
		{
			inp:    utils.HexToBytes("5F0E5F115F425F125F13"),
			expOut: []TlvTag{0x5F0E, 0x5F11, 0x5F42, 0x5F12, 0x5F13},
		},
		{
			inp:    utils.HexToBytes("A0305F1F80887F6002"),
			expOut: []TlvTag{0xA0, 0x30, 0x5F1F, 0x80, 0x88, 0x7F60, 0x02},
		},
	}
	for _, tc := range testCases {
		actOut, err := ParseTags(bytes.NewBuffer(tc.inp))
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		if !reflect.DeepEqual(actOut, tc.expOut) {
			t.Errorf("TLV Tags differs to expected (Exp:%x, Act:%x)", tc.expOut, actOut)
		}
	}
}

func TestGetTagsErr(t *testing.T) {
	// NB adapted from valid test, but we add an incomplete tag (5F), to force a Tag decoding error
	//
	// good: 5F0E5F115F425F125F13
	// bad : 5F0E5F115F425F125F135F
	var data []byte = utils.HexToBytes("5F0E5F115F425F125F135F")

	_, err := ParseTags(bytes.NewBuffer(data))
	if err == nil {
		t.Errorf("error expected")
	}
}

func TestGetTagNoDataErr(t *testing.T) {
	// NB force error by passing empty buffer
	_, err := ParseTag(bytes.NewBuffer([]byte{})) // NB empty buffer
	if err == nil {
		t.Errorf("error expected")
	}
}

func TestEncode(t *testing.T) {
	testCases := []struct {
		tag      TlvTag
		expBytes []byte
	}{
		{
			// negative or 0 tag -> 0x00
			tag:      0,
			expBytes: []byte{0},
		},
		{
			// negative or 0 tag -> 0x00
			tag:      -1,
			expBytes: []byte{0},
		},
		{
			// negative or 0 tag -> 0x00
			tag:      -2147483648,
			expBytes: []byte{0},
		},
		{
			// 32-bit tag is encoded correctly
			tag:      0x1F808000,
			expBytes: []byte{0x1F, 0x80, 0x80, 0x00},
		},
		{
			// max positive 32-bit tag is encoded correctly
			tag:      2147483647,
			expBytes: []byte{0x7F, 0xFF, 0xFF, 0xFF},
		},
	}
	for _, tc := range testCases {
		actBytes := tc.tag.Encode()

		if !bytes.Equal(actBytes, tc.expBytes) {
			t.Errorf("Encoded Tag differs to expected (act:%x, exp:%x)", actBytes, tc.expBytes)
		}
	}
}

func TestIsConstructed(t *testing.T) {
	testCases := []struct {
		tag           TlvTag
		isConstructed bool
	}{
		{
			tag:           0x61,
			isConstructed: true,
		},
		{
			tag:           0x7f61,
			isConstructed: true,
		},
		{
			tag:           0x5f1f,
			isConstructed: false,
		},
		{
			tag:           0x81,
			isConstructed: false,
		},
		{
			tag:           0xFFFFFFFF,
			isConstructed: true,
		},
		{
			tag:           0,
			isConstructed: false,
		},
		{
			tag:           -1,
			isConstructed: false,
		},
	}
	for _, tc := range testCases {
		actIsConstructed := tc.tag.IsConstructed()
		if actIsConstructed != tc.isConstructed {
			t.Errorf("TlvIsConstructedTag error (Tag:%x, Exp:%t, Act:%t)", tc.tag, tc.isConstructed, actIsConstructed)
		}
	}
}
