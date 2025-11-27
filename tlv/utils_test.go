package tlv

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestTagAndLength(t *testing.T) {
	testCases := []struct {
		inpBytes  []byte
		expErr    bool
		expTag    TlvTag
		expLength TlvLength
	}{
		{
			// ok
			inpBytes:  utils.HexToBytes("0102"),
			expErr:    false,
			expTag:    1,
			expLength: 2,
		},
		{
			// ok
			inpBytes:  utils.HexToBytes("028105"),
			expErr:    false,
			expTag:    2,
			expLength: 5,
		},
		{
			// ok
			inpBytes:  utils.HexToBytes("03820502"),
			expErr:    false,
			expTag:    3,
			expLength: 0x0502,
		},
		{
			// error: bad TLV
			inpBytes: utils.HexToBytes("01"),
			expErr:   true,
		},
		{
			// error: bad TLV
			inpBytes: utils.HexToBytes("018210"),
			expErr:   true,
		},
		{
			// error: bad TLV (incomplete multi-byte tag.. e.g. 5F42->5F)
			inpBytes: utils.HexToBytes("5F"),
			expErr:   true,
		},
	}
	for _, tc := range testCases {
		buf := bytes.NewBuffer(tc.inpBytes)

		tag, length, err := TagAndLength(buf)

		if tc.expErr {
			/*
			* error EXPECTED
			 */

			if err == nil {
				t.Errorf("error expected")
			}
		} else {
			/*
			* error NOT expected
			 */

			if err != nil {
				t.Errorf("Unexpected error: %s", err)
			}

			if tag != tc.expTag {
				t.Errorf("Tag differs to expected (Exp:%x, Act:%x)", tc.expTag, tag)
			}

			if length != tc.expLength {
				t.Errorf("Length differs to expected (Exp:%x, Act:%x)", tc.expLength, length)
			}
		}
	}
}
