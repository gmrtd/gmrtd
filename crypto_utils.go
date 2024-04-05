package gmrtd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"log"
	"log/slog"
	"math/big"
	"slices"
)

type BlockCipherAlg int

const (
	DES BlockCipherAlg = iota
	TDES
	AES
)

type HashAlg int

const (
	SHA1 HashAlg = iota
	SHA256
)

const DES_BLOCK_SIZE_BYTES = 8

type KDFCounterType int

const (
	KDF_COUNTER_KSENC KDFCounterType = 1
	KDF_COUNTER_KSMAC KDFCounterType = 2
	KDF_COUNTER_PACE  KDFCounterType = 3
)

type RandomBytesFn func(length int) []byte

type KeyGeneratorEcFn func(ec elliptic.Curve) (pri []byte, pub *EC_POINT)

type EC_POINT struct {
	x *big.Int
	y *big.Int
}

func (ec EC_POINT) String() string {
	return fmt.Sprintf("X:%x, Y:%x", ec.x.Bytes(), ec.y.Bytes())
}

// NB expects double-key(16 bytes) for TDES
func GetCipherForKey(alg BlockCipherAlg, key []byte) cipher.Block {
	var out cipher.Block
	var err error

	switch alg {
	case DES:
		out, err = des.NewCipher(key)
	case TDES:
		out, err = des.NewTripleDESCipher(tdesKey128to192(key))
	case AES:
		out, err = aes.NewCipher(key)
	default:
		err = fmt.Errorf("unsupported cipher (%d)", alg)
	}

	if err != nil {
		log.Panicf("Unable to get cipher (%s)", err.Error())
		return nil
	}

	return out
}

// NB expects keySizeBits=112 for TDES
func KDF(k []byte, c KDFCounterType, alg BlockCipherAlg, keySizeBits int) []byte {
	// combine 'k' and 'c'
	kc := make([]byte, len(k)+4)
	copy(kc, k)
	binary.BigEndian.PutUint32(kc[len(k):], uint32(c))

	var out []byte

	// process based on alg & key-size
	switch alg {
	case TDES:
		switch keySizeBits {
		case 112:
			out = CryptoHash(SHA1, kc)
			out = out[0:16]
			out = DesKeyAdjustParity(out)
		default:
			log.Panicf("Unsupported TDES key-size (key-size(bits):%d)", keySizeBits)
		}
	case AES:
		switch keySizeBits {
		case 128:
			out = CryptoHash(SHA1, kc)
			out = out[0:16]
		case 192:
			out = CryptoHash(SHA256, kc)
			out = out[0:24]
		case 256:
			out = CryptoHash(SHA256, kc)
		default:
			log.Panicf("Unsupported AES key-size (key-size(bits):%d)", keySizeBits)
		}
	default:
		log.Panicf("Unsupported KDF Alg (alg:%d)", alg)
	}

	return out
}

// converts a double-key(16 bytes) to a triple-key(24 bytes)
func tdesKey128to192(key []byte) []byte { // TODO - refer to this as 112 in other place??? should be consistent between 128 and 112
	if len(key) != 128/8 { // 112-bit key
		log.Panicf("Key-length not 128 bits (Act:%d)", len(key)*8)
	}

	out := make([]byte, 24)
	copy(out[0:16], key[0:16])
	copy(out[16:24], key[0:8])

	return out
}

func CryptCBC(blockCipher cipher.Block, iv []byte, data []byte, encrypt bool) []byte {
	// check that the IV length matches the block-size
	if len(iv) != blockCipher.BlockSize() {
		log.Panicf("IV length must match block-size (Act:%d, Exp:%d)", len(iv), blockCipher.BlockSize())
	}
	// check that data length is a multiple of the block-size
	if len(data)%blockCipher.BlockSize() != 0 {
		log.Panicf("Data must be a multiple of block-size (Data-len: %d) (Block-size: %d)", len(data), blockCipher.BlockSize())
	}

	out := make([]byte, len(data))

	var mode cipher.BlockMode
	if encrypt {
		mode = cipher.NewCBCEncrypter(blockCipher, iv)
	} else {
		mode = cipher.NewCBCDecrypter(blockCipher, iv)
	}
	mode.CryptBlocks(out, data)

	return out

}

func ISO9797Method2Pad(data []byte, blockSize int) []byte {
	paddedLen := ((len(data) + blockSize) / blockSize) * blockSize
	out := make([]byte, paddedLen)
	copy(out, data)
	out[len(data)] = 0x80
	// NB no need to add 0's to end of 'out' as it was pre-allocated to next block boundary
	return out
}

// panics if data is not padded
func ISO9797Method2Unpad(data []byte) []byte {
	out := bytes.TrimRight(data, string([]byte{0}))
	if len(out) > 0 {
		if out[len(out)-1] == 0x80 {
			return out[:len(out)-1]
		}
	}
	log.Panicf("Data not padded according to Method-2 (%x -> %x)", data, out)
	return nil
}

// ISO-9797 Retail MAC (DES)
// key: 16 bytes (double) DES key
func ISO9797RetailMacDes(key []byte, data []byte) []byte {
	VerifyByteLength(key, 16)
	if (len(data) < DES_BLOCK_SIZE_BYTES) || (len(data)%DES_BLOCK_SIZE_BYTES != 0) {
		log.Panicf("Data must consist of 1 or more blocks (BlockSize:%d, ActLen:%d)", DES_BLOCK_SIZE_BYTES, len(data))
	}

	k1 := make([]byte, 8)
	k2 := make([]byte, 8)

	copy(k1, key[0:8])
	copy(k2, key[8:16])

	cipherK1 := GetCipherForKey(DES, k1)
	cipherK2 := GetCipherForKey(DES, k2)

	tmp := CryptCBC(cipherK1, make([]byte, DES_BLOCK_SIZE_BYTES), data, true)

	// get last block (8 bytes)
	cbcBlock1 := make([]byte, DES_BLOCK_SIZE_BYTES)
	copy(cbcBlock1, tmp[len(tmp)-DES_BLOCK_SIZE_BYTES:])

	cbcBlock2 := CryptCBC(cipherK2, make([]byte, DES_BLOCK_SIZE_BYTES), cbcBlock1, false)

	return CryptCBC(cipherK1, make([]byte, DES_BLOCK_SIZE_BYTES), cbcBlock2, true)
}

func CryptoHash(alg HashAlg, data []byte) []byte {
	var hashFn hash.Hash

	switch alg {
	case SHA1:
		hashFn = sha1.New()
	case SHA256:
		hashFn = sha256.New()
	default:
		log.Panicf("Unsupported hash algorithm (alg:%d)", alg)
	}

	hashFn.Write(data)

	return hashFn.Sum(nil)
}

func DesKeyAdjustParity(key []byte) []byte {
	out := slices.Clone(key)

	for i := 0; i < len(out); i++ {
		y := byte(out[i] & 0xff)
		parity := 0

		for j := 0; j < 8; j++ {
			parity += int((y >> j) & 1)
		}

		if parity%2 == 0 {
			out[i] ^= 1
		}
	}

	return out
}

func RandomBytes(length int) []byte {
	out := make([]byte, length)
	if n, err := rand.Read(out); (err != nil) || (n != length) {
		log.Panic("Error generating random bytes")
	}
	return out
}

func KeyGeneratorEc(ec elliptic.Curve) (pri []byte, pub *EC_POINT) {
	var err error
	pub = new(EC_POINT)
	pri, pub.x, pub.y, err = elliptic.GenerateKey(ec, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	slog.Debug("KeyGeneratorEc", "Pri", pri, "Pub", pub)
	return
}

func EncodeX962EcPoint(ec elliptic.Curve, point *EC_POINT) []byte {
	return elliptic.Marshal(ec, point.x, point.y)
}

func DecodeX962EcPoint(ec elliptic.Curve, data []byte) *EC_POINT {
	var point EC_POINT
	point.x, point.y = elliptic.Unmarshal(ec, data)
	return &point
}
