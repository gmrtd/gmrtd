package utils

import "testing"

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
