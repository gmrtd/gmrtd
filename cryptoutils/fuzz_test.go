package cryptoutils

import (
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
