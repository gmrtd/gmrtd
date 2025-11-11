package utils

import (
	"bytes"
	"log/slog"
)

// determines whether the data constitutes an image
// return: 'true' if image detected, otherwise 'false'
func IsImage(imageBytes []byte) bool {
	/*
	* Classic JPEG (JFIF/Exif/SPIF/Adobe) files begin with these bytes:
	* 	- FF D8 — SOI
	* 	- followed by FF and a marker (APPn, DQT, etc.)
	* So the minimum reliable check is:
	* 	- byte0 = 0xFF, byte1 = 0xD8, byte2 = 0xFF
	 */
	{
		prefixJpeg := HexToBytes("ffd8ff")

		if bytes.HasPrefix(imageBytes, prefixJpeg) {
			return true
		}
	}

	/*
	* JPEG 2000 (not the same as classic JPEG):
	* 	- JP2 file      : 00 00 00 0C 6A 50 20 20 0D 0A 87 0A
	* 	- Raw codestream: FF 4F FF 51
	 */
	{
		prefixJp2Bitmap := HexToBytes("0000000c6a5020200d0a")
		prefixJp2CodestreamBitmap := HexToBytes("ff4fff51")

		if bytes.HasPrefix(imageBytes, prefixJp2Bitmap) ||
			bytes.HasPrefix(imageBytes, prefixJp2CodestreamBitmap) {
			return true
		}

	}

	slog.Debug("Unknown image type", "prefix", imageBytes[0:10])

	return false
}
