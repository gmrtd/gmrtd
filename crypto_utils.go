package gmrtd

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
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
	return fmt.Sprintf("(x:%x, y:%x)", ec.x.Bytes(), ec.y.Bytes())
}

func (ec EC_POINT) Equal(ec2 EC_POINT) bool {
	if !bytes.Equal(ec.x.Bytes(), ec2.x.Bytes()) || !bytes.Equal(ec.y.Bytes(), ec2.y.Bytes()) {
		return false
	}
	return true
}

// TODO - maybe this should panic.. as this should only be caused by a code issue
// NB supports 8/16/24 byte key lengths for DES
func GetCipherForKey(alg BlockCipherAlg, key []byte) (cipher.Block, error) {
	var out cipher.Block
	var err error

	switch alg {
	case DES:
		out, err = des.NewCipher(key)
	case TDES:
		out, err = des.NewTripleDESCipher(tdesKey(key))
	case AES:
		out, err = aes.NewCipher(key)
	default:
		err = fmt.Errorf("unsupported cipher (%d)", alg)
	}

	// TODO - add tests.... valid... valid alg, but wrong key length... unknown alg

	if err != nil {
		return nil, fmt.Errorf("unable to get cipher (alg:%d) (%w)", alg, err)
	}

	return out, nil
}

// NB expects keySizeBits=112 for TDES
func KDF(k []byte, c KDFCounterType, alg BlockCipherAlg, keySizeBits int) []byte {
	// combine 'k' and 'c'
	kc := bytes.Clone(k)
	kc = append(kc, UInt32ToBytes(uint32(c))...)

	var out []byte

	// process based on alg & key-size
	switch alg {
	case TDES:
		switch keySizeBits {
		case 112:
			out = CryptoHash(crypto.SHA1, kc)
			out = out[0:16]
			out = DesKeyAdjustParity(out)
		default:
			log.Panicf("Unsupported TDES key-size (key-size(bits):%d)", keySizeBits)
		}
	case AES:
		switch keySizeBits {
		case 128:
			out = CryptoHash(crypto.SHA1, kc)
			out = out[0:16]
		case 192:
			out = CryptoHash(crypto.SHA256, kc)
			out = out[0:24]
		case 256:
			out = CryptoHash(crypto.SHA256, kc)
		default:
			log.Panicf("Unsupported AES key-size (key-size(bits):%d)", keySizeBits)
		}
	default:
		log.Panicf("Unsupported KDF Alg (alg:%d)", alg)
	}

	return out
}

// generate a TDES key (24 bytes) from a 8/16/24 byte key
// panics if input key length is invalid
func tdesKey(key []byte) []byte {
	out := make([]byte, 24)

	switch len(key) {
	case 8:
		copy(out[0:8], key[0:8])
		copy(out[8:16], key[0:8])
		copy(out[16:24], key[0:8])
	case 16:
		copy(out[0:16], key[0:16])
		copy(out[16:24], key[0:8])
	case 24:
		// just copy
		copy(out, key)
	default:
		log.Panicf("Invalid input key length (ActBytes:%d, ExpBytes:8/16/24)", len(key))
	}

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

	if cipherK1, err = GetCipherForKey(DES, k1); err != nil {
		return nil, err
	}
	if cipherK2, err = GetCipherForKey(DES, k2); err != nil {
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

// Maps hash algorithm OIDs to crypto.Hash values
var oidHashAlgorithmToCryptoHash = map[string]crypto.Hash{
	oidHashAlgorithmMD5.String():    crypto.MD5,
	oidHashAlgorithmSHA1.String():   crypto.SHA1,
	oidHashAlgorithmSHA256.String(): crypto.SHA256,
	oidHashAlgorithmSHA384.String(): crypto.SHA384,
	oidHashAlgorithmSHA512.String(): crypto.SHA512,
	oidHashAlgorithmSHA224.String(): crypto.SHA224,
}

// hashes the data using the hash algorithm specified by oid
// panics if hash algorithm is not supported
func CryptoHashByOid(oid asn1.ObjectIdentifier, data []byte) []byte {
	hash, ok := oidHashAlgorithmToCryptoHash[oid.String()]

	if !ok {
		log.Panicf("unable to resolve hash algorithm OID (oid: %s)", oid.String())
	}

	return CryptoHash(hash, data)
}

func CryptoHash(alg crypto.Hash, data []byte) []byte {
	var hashFn hash.Hash

	// NB we manually call instead of using '(Hash).New()' to force the hash algorithms to be included in the binary
	switch alg {
	case crypto.MD5:
		hashFn = md5.New()
	case crypto.SHA1:
		hashFn = sha1.New()
	case crypto.SHA224:
		hashFn = sha256.New224()
	case crypto.SHA256:
		hashFn = sha256.New()
	case crypto.SHA384:
		hashFn = sha512.New384()
	case crypto.SHA512:
		hashFn = sha512.New()
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
	slog.Debug("KeyGeneratorEc", "Pri", BytesToHex(pri), "Pub", pub.String())
	return
}

func encodeX962EcPoint(ec elliptic.Curve, point *EC_POINT) []byte {
	return elliptic.Marshal(ec, point.x, point.y)
}

func decodeX962EcPoint(ec elliptic.Curve, data []byte) *EC_POINT {
	var point EC_POINT
	point.x, point.y = elliptic.Unmarshal(ec, data)
	return &point
}
