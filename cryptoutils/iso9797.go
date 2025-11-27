package cryptoutils

import (
	"bytes"
	"crypto/cipher"
	"fmt"
)

func ISO9797Method2Pad(data []byte, blockSize int) []byte {
	paddedLen := ((len(data) + blockSize) / blockSize) * blockSize
	out := make([]byte, paddedLen)
	copy(out, data)
	out[len(data)] = 0x80
	// NB no need to add 0's to end of 'out' as it was pre-allocated to next block boundary
	return out
}

// panics if data is not padded
func ISO9797Method2Unpad(data []byte) ([]byte, error) {
	out := bytes.TrimRight(data, string([]byte{0}))
	if len(out) > 0 {
		if out[len(out)-1] == 0x80 {
			return out[:len(out)-1], nil
		}
	}

	return nil, fmt.Errorf("[ISO9797Method2Unpad] Data is not padded (%x -> %x)", data, out)
}

// ISO-9797 Retail MAC (DES)
// key: 16 bytes (double) DES key
// error: if invalid key length (not 16 bytes) or data not aligned to block boundary (8 bytes)
func ISO9797RetailMacDes(key []byte, data []byte) (mac []byte, err error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("key must be 16 bytes (act:%d)", len(key))
	}
	if (len(data) < DES_BLOCK_SIZE_BYTES) || (len(data)%DES_BLOCK_SIZE_BYTES != 0) {
		return nil, fmt.Errorf("data must consist of 1 or more blocks (BlockSize:%d, ActLen:%d)", DES_BLOCK_SIZE_BYTES, len(data))
	}

	k1 := make([]byte, 8)
	k2 := make([]byte, 8)

	copy(k1, key[0:8])
	copy(k2, key[8:16])

	var cipherK1 cipher.Block
	var cipherK2 cipher.Block

	if cipherK1, err = CipherForKey(DES, k1); err != nil {
		return nil, err
	}
	if cipherK2, err = CipherForKey(DES, k2); err != nil {
		return nil, err
	}

	tmp := CryptCBC(cipherK1, make([]byte, DES_BLOCK_SIZE_BYTES), data, true)

	// get last block (8 bytes)
	cbcBlock1 := make([]byte, DES_BLOCK_SIZE_BYTES)
	copy(cbcBlock1, tmp[len(tmp)-DES_BLOCK_SIZE_BYTES:])

	cbcBlock2 := CryptCBC(cipherK2, make([]byte, DES_BLOCK_SIZE_BYTES), cbcBlock1, false)

	mac = CryptCBC(cipherK1, make([]byte, DES_BLOCK_SIZE_BYTES), cbcBlock2, true)

	return mac, nil
}
