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
			key:         utils.HexToBytes("7E2D2A41C74EA0B38CD36F863939BFA8E9032AAD12345678"),
			counterType: KDF_COUNTER_PACE,
			cipherAlg:   AES,
			keySizeBits: 192,
			expKDF:      utils.HexToBytes("4487bb60d75e55928ab2406733d060bb600c7fa4aeeab92b"),
		},
		{
			key:         utils.HexToBytes("7E2D2A41C74EA0B38CD36F863939BFA8E9032AAD12345678abcdef1234567890"),
			counterType: KDF_COUNTER_PACE,
			cipherAlg:   AES,
			keySizeBits: 256,
			expKDF:      utils.HexToBytes("ac92515edd0f4714cbb46c683cc1a66debb68b3cc34f29904db757ac88988d31"),
		},
	}
	for _, tc := range testCases {
		actKDF := KDF(tc.key, tc.counterType, tc.cipherAlg, tc.keySizeBits)

		if !bytes.Equal(actKDF, tc.expKDF) {
			t.Errorf("KDF failed (Exp:%x) (Act:%x)", tc.expKDF, actKDF)
		}

	}
}

func TestKDFErrTDesKeySize(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	// NB panics as TDES needs to have key-size=112
	KDF([]byte{0x12, 0x34}, KDF_COUNTER_PACE, TDES, 113)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestKDFErrAesKeySize(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	// NB panics as AES does not support key-size=257
	KDF([]byte{0x12, 0x34}, KDF_COUNTER_PACE, AES, 257)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestKDFErrAlg(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	// NB panics as Alg=99 is unsupported
	KDF([]byte{0x12, 0x34}, KDF_COUNTER_PACE, 99, 256)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}
