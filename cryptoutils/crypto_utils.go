// Package cryptoutils provides cryptographic utility functions.
package cryptoutils

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
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

func (ecKeypair EcKeypair) String() string {
	return fmt.Sprintf("(Pri:%x, Pub:%s)", ecKeypair.Pri, ecKeypair.Pub.String())
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
		// Note: suppress weak cipher warning in sonar
		//		 - DES is required as it is used by 'ISO9797RetailMacDes'
		out, err = des.NewCipher(key) // NOSONAR
	case TDES:
		var tmpTDesKey []byte
		tmpTDesKey, err = tdesKey(key)
		if err == nil {
			// Note: suppress weak cipher warning in sonar
			//		 - TDES is required as it is used by BAC/PACE
			out, err = des.NewTripleDESCipher(tmpTDesKey) // NOSONAR
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
		panic(fmt.Sprintf("[CryptCBC] IV length must match block-size (Act:%d, Exp:%d)", len(iv), blockCipher.BlockSize()))
	}
	// check that data length is a multiple of the block-size
	if len(data)%blockCipher.BlockSize() != 0 {
		panic(fmt.Sprintf("[CryptCBC] Data must be a multiple of block-size (Data-len: %d) (Block-size: %d)", len(data), blockCipher.BlockSize()))
	}

	out := make([]byte, len(data))

	var mode cipher.BlockMode
	if encrypt {
		// Note: suppress secure mode and padding scheme warning in sonar
		//		 - CBC is used by BAC/PACE
		mode = cipher.NewCBCEncrypter(blockCipher, iv) // NOSONAR
	} else {
		// Note: suppress secure mode and padding scheme warning in sonar
		//		 - CBC is used by BAC/PACE
		mode = cipher.NewCBCDecrypter(blockCipher, iv) // NOSONAR
	}
	mode.CryptBlocks(out, data)

	return out

}

// Maps hash algorithm OIDs to crypto.Hash values
var oidHashAlgorithmToCryptoHash = map[string]crypto.Hash{
	oid.OidHashAlgorithmMD5.String():    crypto.MD5,
	oid.OidHashAlgorithmSHA1.String():   crypto.SHA1,
	oid.OidHashAlgorithmSHA224.String(): crypto.SHA224,
	oid.OidHashAlgorithmSHA256.String(): crypto.SHA256,
	oid.OidHashAlgorithmSHA384.String(): crypto.SHA384,
	oid.OidHashAlgorithmSHA512.String(): crypto.SHA512,
}

// panics if hash algorithm is not supported
func CryptoHashOidToAlg(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	hash, ok := oidHashAlgorithmToCryptoHash[oid.String()]

	if !ok {
		return 0, fmt.Errorf("[CryptoHashOidToAlg] unable to resolve hash algorithm OID (oid: %s)", oid.String())
	}

	return hash, nil
}

// hashes the data using the hash algorithm specified by oid
// panics if hash algorithm is not supported
func CryptoHashByOid(oid asn1.ObjectIdentifier, data []byte) ([]byte, error) {
	hashAlg, err := CryptoHashOidToAlg(oid)
	if err != nil {
		return nil, fmt.Errorf("[CryptoHashByOid] CryptoHashOidToAlg error: %w", err)
	}

	return CryptoHash(hashAlg, data), nil
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
		panic(fmt.Sprintf("[CryptoHash] Unsupported hash algorithm (alg:%d)", alg))
	}

	hashFn.Write(data)

	return hashFn.Sum(nil)
}

func CryptoHashDigestSize(alg crypto.Hash) int {
	// this is a bit of a hack, but we do a dummy hash to calculate the size
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

	slog.Debug("KeyGeneratorEc", "Keypair", out.String())

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
		panic(fmt.Sprintf("[RsaDecryptWithPublicKey] ciphertext too short (len:%01d)", len(ciphertext)))
	}

	m := new(big.Int).SetBytes(ciphertext)
	e := big.NewInt(int64(publicKey.E))
	c := new(big.Int).Exp(m, e, publicKey.N)

	return c.Bytes()
}

func CryptoHashFromEcPubKey(pub *ecdsa.PublicKey) crypto.Hash {
	nbits := pub.Params().N.BitLen()
	switch {
	case nbits >= 512:
		return crypto.SHA512
	case nbits >= 384:
		return crypto.SHA384
	case nbits >= 256:
		return crypto.SHA256
	default:
		// 224-bit curves or smaller
		return crypto.SHA224
	}
}

// support for P192 (secp-192r1) which is required by some countries but not supported by the go libraries
func EllipticP192() elliptic.Curve {
	var curveParams *elliptic.CurveParams = &elliptic.CurveParams{
		Name:    "P-192",
		BitSize: 192,
		P:       new(big.Int).SetBytes(utils.HexToBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF")),
		N:       new(big.Int).SetBytes(utils.HexToBytes("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831")),
		B:       new(big.Int).SetBytes(utils.HexToBytes("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1")),
		Gx:      new(big.Int).SetBytes(utils.HexToBytes("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012")),
		Gy:      new(big.Int).SetBytes(utils.HexToBytes("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811")),
	}

	return curveParams
}
