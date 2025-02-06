package utils

import (
	"bytes"
	"log/slog"
)

// determines whether the data constitutes an image
// return: 'true' if image detected, otherwise 'false'
func IsImage(imageBytes []byte) bool {
	// TODO - review following code as it seems to support more variants...
	//			https://gist.github.com/kvanh/76378993ed5de2182f762e19eccf36a0

	prefixJpeg := HexToBytes("ffd8ffe000104a464946")
	prefixJp2Bitmap := HexToBytes("0000000c6a5020200d0a")
	prefixJp2CodestreamBitmap := HexToBytes("ff4fff51")

	if !bytes.HasPrefix(imageBytes, prefixJpeg) &&
		!bytes.HasPrefix(imageBytes, prefixJp2Bitmap) &&
		!bytes.HasPrefix(imageBytes, prefixJp2CodestreamBitmap) {
		slog.Debug("Unknown image type", "prefix", imageBytes[0:10])
		return false
	}

	return true
}
