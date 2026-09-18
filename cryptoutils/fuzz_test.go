package cryptoutils

import (
	"crypto/elliptic"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

// FuzzISO9797Method2Unpad fuzzes the padding-removal step applied to decrypted
// secure-messaging plaintext (iso7816.SecureMessaging.cryptoUnpad). Standalone
// []byte -> ([]byte, error), no session/receiver needed.
func FuzzISO9797Method2Unpad(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(utils.HexToBytes("123456788080"))
	f.Add(utils.HexToBytes("12348000000000"))
	f.Add(utils.HexToBytes("800000"))
	f.Add([]byte{0x12, 0x34, 0x56, 0x78}) // not padded

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ISO9797Method2Unpad(data)
	})
}

// FuzzDecodeX962EcPoint fuzzes the X9.62 EC public-point decoder, called on
// chip-supplied bytes in several places (PACE/Chip Authentication dynamic auth
// data, evidence replay, and CMS certificate public keys) — see cryptoutils_test.go's
// TestDecodeX962EcPoint for the same curve/error-shape cases used as seeds here.
func FuzzDecodeX962EcPoint(f *testing.F) {
	p256 := elliptic.P256()
	validP256Uncompressed := elliptic.Marshal(p256, p256.Params().Gx, p256.Params().Gy)

	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(validP256Uncompressed)
	f.Add(validP256Uncompressed[:len(validP256Uncompressed)-1]) // truncated
	f.Add([]byte{0x04, 0x01, 0x02, 0x03, 0x04})                 // random invalid bytes
	f.Add(append([]byte{0x05}, validP256Uncompressed[1:]...))   // wrong format prefix

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeX962EcPoint(p256, data)
	})
}
