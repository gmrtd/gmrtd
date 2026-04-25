package cryptoutils

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestISO9797Method2Pad(t *testing.T) {
	testCases := []struct {
		data      []byte
		blockSize int
		exp       []byte
	}{
		{
			data:      utils.HexToBytes("1234567880"),
			blockSize: 8,
			exp:       utils.HexToBytes("1234567880800000"),
		},
		{
			data:      utils.HexToBytes("1234"),
			blockSize: 8,
			exp:       utils.HexToBytes("1234800000000000"),
		},
		{
			data:      utils.HexToBytes(""),
			blockSize: 8,
			exp:       utils.HexToBytes("8000000000000000"),
		},
		{
			data:      utils.HexToBytes("1234567890ABCDEF"),
			blockSize: 8,
			exp:       utils.HexToBytes("1234567890ABCDEF8000000000000000"),
		},
	}
	for _, tc := range testCases {
		out := ISO9797Method2Pad(tc.data, tc.blockSize)

		if !bytes.Equal(tc.exp, out) {
			t.Errorf("Pad failed (Exp:%x) (Act:%x)", tc.exp, out)
		}
	}
}

func TestISO9797Method2Unpad(t *testing.T) {
	testCases := []struct {
		in  []byte
		exp []byte
	}{
		{
			in:  utils.HexToBytes("123456788080"),
			exp: utils.HexToBytes("1234567880"),
		},
		{
			in:  utils.HexToBytes("12348000000000"),
			exp: utils.HexToBytes("1234"),
		},
		{
			in:  utils.HexToBytes("800000"),
			exp: utils.HexToBytes(""),
		},
	}
	for _, tc := range testCases {
		actBytes, err := ISO9797Method2Unpad(tc.in)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		if !bytes.Equal(tc.exp, actBytes) {
			t.Errorf("Unpad failed (Exp:%x) (Act:%x)", tc.exp, actBytes)
		}
	}
}

func TestISO9797Method2UnpadErr(t *testing.T) {
	var data []byte = []byte{0x12, 0x34, 0x56, 0x78}

	// NB error as the data is not padded correctly
	_, err := ISO9797Method2Unpad(data)

	if err == nil {
		t.Errorf("error expected")
	}
}

func TestISO9797RetailMacDesErrors(t *testing.T) {
	// NB: ISO9797 Retail MAC requires 16-byte DES key
	testCases := []struct {
		key  []byte
		data []byte
	}{
		{
			// bad key length (8 bytes instead of 16)
			key:  utils.HexToBytes("0123456789ABCDEF"),
			data: utils.HexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
		},
		{
			// bad key length (24 bytes instead of 16)
			key:  utils.HexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
			data: utils.HexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
		},
		{
			// data not aligned with block boundary (ie not multiple of 8 bytes)
			key:  utils.HexToBytes("0123456789ABCDEF0123456789ABCDEF"),
			data: utils.HexToBytes("0123456789ABCDEF01"),
		},
	}
	for _, tc := range testCases {
		mac, err := ISO9797RetailMacDes(tc.key, tc.data)

		if err == nil {
			t.Errorf("Error expected")
		}

		if mac != nil {
			t.Errorf("MAC not expected for error case")
		}
	}
}

func TestISO9797RetailMacDes(t *testing.T) {
	testCases := []struct {
		key    []byte
		data   []byte
		expMac []byte
	}{
		{
			key:    utils.HexToBytes("e3857ca24946251c151c540e13f2cd51"),
			data:   utils.HexToBytes("00000000000000cd0c88000080000000871101ed7f8cb47a4eea086324a7f9dd7427809701008000"),
			expMac: utils.HexToBytes("97f54bae49aa71f8"),
		},
		{
			key:    utils.HexToBytes("7962d9ece03d1acd4c76089dce131543"),
			data:   utils.HexToBytes("46b9342a41396cd7386bf5803104d7cedc122b9132139baf2eedc94ee178534f8000000000000000"),
			expMac: utils.HexToBytes("2f2d235d074d7449"),
		},
		{
			key:    utils.HexToBytes("d6c47ff4677ac8ae91cb49f4ce673432"),
			data:   utils.HexToBytes("9646c154bfb7be7c0c86000080000000874901a9c6bf370c62aa43ca1ec9b97071727654822361deb8ba4e5719aa05d8e86aa36164dfa5e506dbf60dc7418858179fd25dac5e9e49393dde37e29652444941b562142ab5f19aea919701008000"),
			expMac: utils.HexToBytes("5083316637060c4d"),
		},
		{
			key:    utils.HexToBytes("c1bc1f075797b970b5a45e64a764b0cb"),
			data:   utils.HexToBytes("7f494f060a04007f000702020402018641042dbaf62e6fdfb31eb66f206493b9e7721586f0e5c93754d7bd5a884ca251ee4d720ab539a60561bc46812fa289b58ac69f0c6e32adbaf7241049a31211f80f5b800000000000"),
			expMac: utils.HexToBytes("8d7c617d43efe09e"),
		},
	}
	for _, tc := range testCases {
		mac, err := ISO9797RetailMacDes(tc.key, tc.data)

		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		} else if !bytes.Equal(mac, tc.expMac) {
			t.Errorf("MAC differs to expected (exp:%x) (act:%x)", tc.expMac, mac)
		}
	}
}

func TestISO9797RetailMacDesWithDepsErrorCases(t *testing.T) {
	validKey := make([]byte, 16)
	validData := make([]byte, DES_BLOCK_SIZE_BYTES)

	errBoom := errors.New("boom")

	tests := []struct {
		name          string
		key           []byte
		data          []byte
		cipherForKey  blockCipherFactory
		cryptCBC      cbcCryptFunc
		wantErr       error
		wantErrString string
	}{
		{
			name:          "invalid key length",
			key:           make([]byte, 15),
			data:          validData,
			cipherForKey:  nil,
			cryptCBC:      nil,
			wantErrString: "key must be 16 bytes",
		},
		{
			name:          "data less than one block",
			key:           validKey,
			data:          make([]byte, DES_BLOCK_SIZE_BYTES-1),
			cipherForKey:  nil,
			cryptCBC:      nil,
			wantErrString: "data must consist of 1 or more blocks",
		},
		{
			name:          "data not block aligned",
			key:           validKey,
			data:          make([]byte, DES_BLOCK_SIZE_BYTES+1),
			cipherForKey:  nil,
			cryptCBC:      nil,
			wantErrString: "data must consist of 1 or more blocks",
		},
		{
			name: "cipherForKey K1 error",
			key:  validKey,
			data: validData,
			cipherForKey: func(alg BlockCipherAlg, key []byte) (cipher.Block, error) {
				return nil, errBoom
			},
			cryptCBC:      nil,
			wantErr:       errBoom,
			wantErrString: "cipherForKey(K1) error",
		},
		{
			name: "cipherForKey K2 error",
			key:  validKey,
			data: validData,
			cipherForKey: func() blockCipherFactory {
				calls := 0
				return func(alg BlockCipherAlg, key []byte) (cipher.Block, error) {
					calls++
					if calls == 2 {
						return nil, errBoom
					}
					return CipherForKey(alg, key)
				}
			}(),
			cryptCBC:      nil,
			wantErr:       errBoom,
			wantErrString: "cipherForKey(K2) error",
		},
		{
			name:         "cryptCBC 1 error",
			key:          validKey,
			data:         validData,
			cipherForKey: CipherForKey,
			cryptCBC: func(block cipher.Block, iv []byte, data []byte, encrypt bool) ([]byte, error) {
				return nil, errBoom
			},
			wantErr:       errBoom,
			wantErrString: "cryptCBC(1) error",
		},
		{
			name:         "cryptCBC 2 error",
			key:          validKey,
			data:         validData,
			cipherForKey: CipherForKey,
			cryptCBC: func() cbcCryptFunc {
				calls := 0
				return func(block cipher.Block, iv []byte, data []byte, encrypt bool) ([]byte, error) {
					calls++
					if calls == 2 {
						return nil, errBoom
					}
					return CryptCBC(block, iv, data, encrypt)
				}
			}(),
			wantErr:       errBoom,
			wantErrString: "cryptCBC(2) error",
		},
		{
			name:         "cryptCBC 3 error",
			key:          validKey,
			data:         validData,
			cipherForKey: CipherForKey,
			cryptCBC: func() cbcCryptFunc {
				calls := 0
				return func(block cipher.Block, iv []byte, data []byte, encrypt bool) ([]byte, error) {
					calls++
					if calls == 3 {
						return nil, errBoom
					}
					return CryptCBC(block, iv, data, encrypt)
				}
			}(),
			wantErr:       errBoom,
			wantErrString: "cryptCBC(3) error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := iso9797RetailMacDesWithDeps(
				tc.key,
				tc.data,
				tc.cipherForKey,
				tc.cryptCBC,
			)

			if err == nil {
				t.Fatalf("Error expected")
			}

			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Wanted '%s' got '%s'", tc.wantErr, err)
			}

			if !strings.Contains(err.Error(), tc.wantErrString) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErrString, err.Error())
			}
		})
	}
}
