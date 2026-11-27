package cryptoutils

import (
	"bytes"
	"crypto/cipher"
	"fmt"
)

// ISO9797Method2Pad returns a copy of data padded per ISO/IEC 9797-1 padding method 2: a 0x80
// byte then zero bytes up to a multiple of blockSize. A full block is added if data is aligned.
func ISO9797Method2Pad(data []byte, blockSize int) []byte {
	paddedLen := ((len(data) + blockSize) / blockSize) * blockSize
	out := make([]byte, paddedLen)
	copy(out, data)
	out[len(data)] = 0x80
	// NB no need to add 0's to end of 'out' as it was pre-allocated to next block boundary
	return out
}

// ISO9797Method2UnpadBlock removes ISO/IEC 9797-1 padding method 2 from data, which must be a
// non-empty multiple of blockSize: the padding is a 0x80 byte followed by zero bytes, all within
// the final block. It returns a copy of the unpadded data, or an error if data is not padded
// that way.
//
// The input is typically decrypted secure-messaging plaintext, i.e. chip file contents, so the
// error reports lengths only, never the data.
func ISO9797Method2UnpadBlock(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("[ISO9797Method2UnpadBlock] data length %d is not a non-zero multiple of the block size %d", len(data), blockSize)
	}
	lastBlock := len(data) - blockSize
	i := len(data) - 1
	for i > lastBlock && data[i] == 0x00 {
		i--
	}
	if data[i] != 0x80 {
		return nil, fmt.Errorf("[ISO9797Method2UnpadBlock] data is not padded (len:%d)", len(data))
	}
	return bytes.Clone(data[:i]), nil
}

// ISO9797Method2Unpad removes ISO/IEC 9797-1 padding method 2 by stripping all trailing zero
// bytes and then a single 0x80 byte, without regard to block boundaries. It returns a copy of
// the unpadded data, or an error if no 0x80 byte remains. The error reports the length only,
// never the data.
//
// Deprecated: Use ISO9797Method2UnpadBlock, which also checks that the padding lies within
// the final block.
func ISO9797Method2Unpad(data []byte) ([]byte, error) {
	out := bytes.TrimRight(data, string([]byte{0}))
	if len(out) > 0 && out[len(out)-1] == 0x80 {
		return bytes.Clone(out[:len(out)-1]), nil
	}
	return nil, fmt.Errorf("[ISO9797Method2Unpad] data is not padded (len:%d)", len(data))
}

type blockCipherFactory func(alg BlockCipherAlg, key []byte) (cipher.Block, error)

type cbcCryptFunc func(
	block cipher.Block,
	iv []byte,
	data []byte,
	encrypt bool,
) ([]byte, error)

// ISO-9797 Retail MAC (DES)
// key: 16 bytes (double) DES key
// error: if invalid key length (not 16 bytes) or data not aligned to block boundary (8 bytes)
func ISO9797RetailMacDes(key, data []byte) ([]byte, error) {
	return iso9797RetailMacDesWithDeps(key, data, CipherForKey, CryptCBC)
}

func iso9797RetailMacDesWithDeps(
	key, data []byte,
	cipherForKey blockCipherFactory,
	cryptCBC cbcCryptFunc,
) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("key must be 16 bytes (act:%d)", len(key))
	}
	if (len(data) < DES_BLOCK_SIZE_BYTES) || (len(data)%DES_BLOCK_SIZE_BYTES != 0) {
		return nil, fmt.Errorf("data must consist of 1 or more blocks (BlockSize:%d, ActLen:%d)", DES_BLOCK_SIZE_BYTES, len(data))
	}

	k1 := make([]byte, 8)
	copy(k1, key[0:8])

	k2 := make([]byte, 8)
	copy(k2, key[8:16])

	var err error

	var cipherK1 cipher.Block
	if cipherK1, err = cipherForKey(DES, k1); err != nil {
		return nil, fmt.Errorf("[iso9797RetailMacDesWithDeps] cipherForKey(K1) error: %w", err)
	}

	var cipherK2 cipher.Block
	if cipherK2, err = cipherForKey(DES, k2); err != nil {
		return nil, fmt.Errorf("[iso9797RetailMacDesWithDeps] cipherForKey(K2) error: %w", err)
	}

	tmp, err := cryptCBC(cipherK1, make([]byte, DES_BLOCK_SIZE_BYTES), data, true)
	if err != nil {
		return nil, fmt.Errorf("[iso9797RetailMacDesWithDeps] cryptCBC(1) error: %w", err)
	}

	// get last block (8 bytes)
	cbcBlock1 := make([]byte, DES_BLOCK_SIZE_BYTES)
	copy(cbcBlock1, tmp[len(tmp)-DES_BLOCK_SIZE_BYTES:])

	cbcBlock2, err := cryptCBC(cipherK2, make([]byte, DES_BLOCK_SIZE_BYTES), cbcBlock1, false)
	if err != nil {
		return nil, fmt.Errorf("[iso9797RetailMacDesWithDeps] cryptCBC(2) error: %w", err)
	}

	var mac []byte
	mac, err = cryptCBC(cipherK1, make([]byte, DES_BLOCK_SIZE_BYTES), cbcBlock2, true)
	if err != nil {
		return nil, fmt.Errorf("[iso9797RetailMacDesWithDeps] cryptCBC(3) error: %w", err)
	}

	return mac, nil
}
