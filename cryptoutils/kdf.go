package cryptoutils

import (
	"bytes"
	"crypto"
	"fmt"

	"github.com/gmrtd/gmrtd/utils"
)

// KDFCounterType is the 32-bit counter c that KDF appends to the shared secret.
type KDFCounterType int

// KDF counter values defined by ICAO Doc 9303 Part 11: 1 derives an encryption key, 2 a MAC
// key and 3 the PACE password key.
const (
	KDF_COUNTER_KSENC KDFCounterType = 1
	KDF_COUNTER_KSMAC KDFCounterType = 2
	KDF_COUNTER_PACE  KDFCounterType = 3
)

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
			panic(fmt.Sprintf("Unsupported TDES key-size (key-size(bits):%d)", keySizeBits))
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
			panic(fmt.Sprintf("Unsupported AES key-size (key-size(bits):%d)", keySizeBits))
		}
	default:
		panic(fmt.Sprintf("Unsupported KDF Alg (alg:%d)", alg))
	}

	return out
}
