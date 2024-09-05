package cryptoutils

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestKDF(t *testing.T) {
	testCases := []struct {
		key         []byte
		counterType KDFCounterType
		cipherAlg   BlockCipherAlg
		keySizeBits int
		expKDF      []byte
	}{
		{
			key:         utils.HexToBytes("28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925"),
			counterType: KDF_COUNTER_KSENC,
			cipherAlg:   AES,
			keySizeBits: 128,
			expKDF:      utils.HexToBytes("F5F0E35C0D7161EE6724EE513A0D9A7F"),
		},
		{
			key:         utils.HexToBytes("28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925"),
			counterType: KDF_COUNTER_KSMAC,
			cipherAlg:   AES,
			keySizeBits: 128,
			expKDF:      utils.HexToBytes("FE251C7858B356B24514B3BD5F4297D1"),
		},
		{
			key:         utils.HexToBytes("7E2D2A41C74EA0B38CD36F863939BFA8E9032AAD"),
			counterType: KDF_COUNTER_PACE,
			cipherAlg:   AES,
			keySizeBits: 128,
			expKDF:      utils.HexToBytes("89DED1B26624EC1E634C1989302849DD"),
		},
		{
			key:         utils.HexToBytes("239AB9CB282DAF66231DC5A4DF6BFBAE"),
			counterType: KDF_COUNTER_KSENC,
			cipherAlg:   TDES,
			keySizeBits: 112,
			expKDF:      utils.HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F2"),
		},
		{
			key:         utils.HexToBytes("239AB9CB282DAF66231DC5A4DF6BFBAE"),
			counterType: KDF_COUNTER_KSMAC,
			cipherAlg:   TDES,
			keySizeBits: 112,
			expKDF:      utils.HexToBytes("7962D9ECE03D1ACD4C76089DCE131543"),
		},
	}
	for _, tc := range testCases {
		actKDF := KDF(tc.key, tc.counterType, tc.cipherAlg, tc.keySizeBits)

		if !bytes.Equal(actKDF, tc.expKDF) {
			t.Errorf("KDF failed (Exp:%x) (Act:%x)", tc.expKDF, actKDF)
		}

	}
}
