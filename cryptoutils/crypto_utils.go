// Package cryptoutils provides cryptographic utility functions.
package cryptoutils

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

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
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

type KeyGeneratorEcFn func(ec elliptic.Curve) EcKeypair

type EcKeypair struct {
	Pri []byte
	Pub *EcPoint
}

type EcPoint struct {
	X *big.Int
	Y *big.Int
}

// https://www.itu.int/ITU-T/formal-language/itu-t/x/x894/2018-cor1/ANSI-X9-62.html
//
// -- Type (parameterized) to indicate the hash function with
// -- the OID ecdsa-with-Specified
// HashAlgorithm::= AlgorithmIdentifier {{ ANSIX9HashFunctions }}
//
// -- Finite field element
// FieldElement ::= OCTET STRING
//
// -- Finite fields have a type (prime or binary) and parameters (size and basis)
// FieldID { FIELD-ID:IOSet } ::= SEQUENCE {-- Finite field
// 	fieldType		FIELD-ID.&id({IOSet}),
// 	parameters		FIELD-ID.&Type({IOSet}{@fieldType})
// 	}
// 	-- ============================================
// 	-- Elliptic Curve Points (see  E.6)
// 	-- ============================================
// 	ECPoint ::= OCTET STRING
// 	-- ============================================
// 	-- Elliptic Curve Domain Parameters (see  E.7)
// 	-- ============================================
// 	-- Identifying an elliptic curve by its coefficients (and optional seed)
// 	Curve ::= SEQUENCE {
// 	a		FieldElement, -- Elliptic curve coefficient a
// 	b		FieldElement, -- Elliptic curve coefficient b
// 	seed	BIT STRING OPTIONAL
// 	-- Shall be present if used in SpecifiedECDomain with version of
// 	-- ecdpVer2 or ecdpVer3
// 	}
// 	-- Type used to control version of EC domain parameters
// 	SpecifiedECDomainVersion ::= INTEGER { ecdpVer1(1) , ecdpVer2(2) , ecdpVer3(3) }
// 	-- Identifying elliptic curve domain parameters explicitly with this type
// 	SpecifiedECDomain ::= SEQUENCE {
// 	version		SpecifiedECDomainVersion ( ecdpVer1 | ecdpVer2 | ecdpVer3 ),
// 	fieldID		FieldID {{FieldTypes}},
// 	curve		Curve,
// 	base			ECPoint, -- Base point G
// 	order		INTEGER, -- Order n of the base point
// 	cofactor		INTEGER OPTIONAL, -- The integer h = #E(Fq)/n
// 	hash			HashAlgorithm OPTIONAL,
// 	... -- Additional parameters may be added
// 	}

// TODO - consider aligning above to RFC-3279.. ECParameters ?

// TODO - following xcode could be moved to a generic crypto module

type ECCurve struct {
	A    []byte
	B    []byte
	Seed asn1.BitString `asn1:"optional"`
}

type ECField struct {
	FieldType  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

// RFC 3279 (RSA Keys)
type RsaPublicKey struct {
	N *big.Int
	E int
}

func (ec EcPoint) String() string {
	return fmt.Sprintf("(x:%x, y:%x)", ec.X.Bytes(), ec.Y.Bytes())
}

func (ec EcPoint) Equal(ec2 EcPoint) bool {
	if !bytes.Equal(ec.X.Bytes(), ec2.X.Bytes()) || !bytes.Equal(ec.Y.Bytes(), ec2.Y.Bytes()) {
		return false
	}
	return true
}

// NB supports 8/16/24 byte key lengths for DES
func GetCipherForKey(alg BlockCipherAlg, key []byte) (cipher.Block, error) {
	var out cipher.Block
	var err error

	switch alg {
	case DES:
		out, err = des.NewCipher(key)
	case TDES:
		var tmpTDesKey []byte
		tmpTDesKey, err = tdesKey(key)
		if err == nil {
			out, err = des.NewTripleDESCipher(tmpTDesKey)
		}
	case AES:
		out, err = aes.NewCipher(key)
	default:
		err = fmt.Errorf("unsupported cipher (%d)", alg)
	}

	if err != nil {
		return nil, fmt.Errorf("unable to get cipher (alg:%d) (%w)", alg, err)
	}

	return out, nil
}

// NB expects keySizeBits=112 for TDES
func KDF(k []byte, c KDFCounterType, alg BlockCipherAlg, keySizeBits int) []byte {
	// combine 'k' and 'c'
	kc := bytes.Clone(k)
	kc = append(kc, utils.UInt32ToBytes(uint32(c))...)

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
// returns error if input key length is invalid
func tdesKey(key []byte) ([]byte, error) {
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
		return nil, fmt.Errorf("invalid input key length (ActBytes:%d, ExpBytes:8/16/24)", len(key))
	}

	return out, nil
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
	oid.OidHashAlgorithmMD5.String():    crypto.MD5,
	oid.OidHashAlgorithmSHA1.String():   crypto.SHA1,
	oid.OidHashAlgorithmSHA256.String(): crypto.SHA256,
	oid.OidHashAlgorithmSHA384.String(): crypto.SHA384,
	oid.OidHashAlgorithmSHA512.String(): crypto.SHA512,
	oid.OidHashAlgorithmSHA224.String(): crypto.SHA224,
}

// panics if hash algorithm is not supported
func CryptoHashOidToAlg(oid asn1.ObjectIdentifier) crypto.Hash {
	hash, ok := oidHashAlgorithmToCryptoHash[oid.String()]

	if !ok {
		log.Panicf("unable to resolve hash algorithm OID (oid: %s)", oid.String())
	}

	return hash
}

// hashes the data using the hash algorithm specified by oid
// panics if hash algorithm is not supported
func CryptoHashByOid(oid asn1.ObjectIdentifier, data []byte) []byte {
	hashAlg := CryptoHashOidToAlg(oid)

	return CryptoHash(hashAlg, data)
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

func CryptoHashDigestSize(alg crypto.Hash) int {
	// TODO - this is a bit of a hack... ideally we'd take directly from the hash-alg
	return len(CryptoHash(alg, []byte{}))
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

func KeyGeneratorEc(ec elliptic.Curve) EcKeypair {
	var err error
	var out EcKeypair

	out.Pub = new(EcPoint)

	out.Pri, out.Pub.X, out.Pub.Y, err = elliptic.GenerateKey(ec, rand.Reader)
	if err != nil {
		log.Panic(err)
	}

	slog.Debug("KeyGeneratorEc", "Pri", utils.BytesToHex(out.Pri), "Pub", out.Pub.String())

	return out
}

func EncodeX962EcPoint(ec elliptic.Curve, point *EcPoint) []byte {
	return elliptic.Marshal(ec, point.X, point.Y)
}

func DecodeX962EcPoint(ec elliptic.Curve, data []byte) *EcPoint {
	var point EcPoint
	point.X, point.Y = elliptic.Unmarshal(ec, data)
	return &point
}

func DoEcDh(localPrivate []byte, remotePublic *EcPoint, ec elliptic.Curve) *EcPoint {
	var point EcPoint
	point.X, point.Y = ec.ScalarMult(remotePublic.X, remotePublic.Y, localPrivate)
	slog.Debug("DoECDH", "Pri", utils.BytesToHex(localPrivate), "Pub", remotePublic, "EC.P", utils.BytesToHex(ec.Params().P.Bytes()), "Res", point)
	return &point
}

func RsaDecryptWithPublicKey(ciphertext []byte, publicKey RsaPublicKey) []byte {
	if len(ciphertext) < 1 {
		log.Panicf("ciphertext too short (len:%01d)", len(ciphertext))
	}

	m := new(big.Int).SetBytes(ciphertext)
	e := big.NewInt(int64(publicKey.E))
	c := new(big.Int).Exp(m, e, publicKey.N)

	return c.Bytes()
}
