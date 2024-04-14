package gmrtd

import (
	"bytes"
	"crypto/cipher"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/ebfe/brainpool"
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
			key:         HexToBytes("28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925"),
			counterType: KDF_COUNTER_KSENC,
			cipherAlg:   AES,
			keySizeBits: 128,
			expKDF:      HexToBytes("F5F0E35C0D7161EE6724EE513A0D9A7F"),
		},
		{
			key:         HexToBytes("28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925"),
			counterType: KDF_COUNTER_KSMAC,
			cipherAlg:   AES,
			keySizeBits: 128,
			expKDF:      HexToBytes("FE251C7858B356B24514B3BD5F4297D1"),
		},
		{
			key:         HexToBytes("7E2D2A41C74EA0B38CD36F863939BFA8E9032AAD"),
			counterType: KDF_COUNTER_PACE,
			cipherAlg:   AES,
			keySizeBits: 128,
			expKDF:      HexToBytes("89DED1B26624EC1E634C1989302849DD"),
		},
		{
			key:         HexToBytes("239AB9CB282DAF66231DC5A4DF6BFBAE"),
			counterType: KDF_COUNTER_KSENC,
			cipherAlg:   TDES,
			keySizeBits: 112,
			expKDF:      HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F2"),
		},
		{
			key:         HexToBytes("239AB9CB282DAF66231DC5A4DF6BFBAE"),
			counterType: KDF_COUNTER_KSMAC,
			cipherAlg:   TDES,
			keySizeBits: 112,
			expKDF:      HexToBytes("7962D9ECE03D1ACD4C76089DCE131543"),
		},
	}
	for _, tc := range testCases {
		actKDF := KDF(tc.key, tc.counterType, tc.cipherAlg, tc.keySizeBits)

		if !bytes.Equal(actKDF, tc.expKDF) {
			t.Errorf("KDF failed (Exp:%x) (Act:%x)", tc.expKDF, actKDF)
		}

	}
}

func TestTDesKey128to192(t *testing.T) {
	inp := []byte{0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F, 0x76, 0xF2}
	exp := []byte{0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F, 0x76, 0xF2, 0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF}

	out := tdesKey128to192(inp)

	if !bytes.Equal(exp, out) {
		t.Errorf("TDes key expansion failed")
	}
}

func TestCryptCBC(t *testing.T) {
	testCases := []struct {
		alg     BlockCipherAlg
		key     []byte
		iv      []byte
		encrypt bool
		in      []byte
		out     []byte
	}{
		{
			alg:     TDES, // double-key
			key:     HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F2"),
			iv:      make([]byte, 8),
			encrypt: true,
			in:      HexToBytes("781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B"),
			out:     HexToBytes("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2"),
		},
		{
			alg:     TDES, // double-key
			key:     HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F2"),
			iv:      make([]byte, 8),
			encrypt: false,
			in:      HexToBytes("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2"),
			out:     HexToBytes("781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B"),
		},
		{
			alg:     AES, // 128
			key:     HexToBytes("2B7E151628AED2A6ABF7158809CF4F3C"),
			iv:      HexToBytes("000102030405060708090A0B0C0D0E0F"),
			encrypt: true,
			in:      HexToBytes("6BC1BEE22E409F96E93D7E117393172A"),
			out:     HexToBytes("7649ABAC8119B246CEE98E9B12E9197D"),
		},
		{
			alg:     AES, // 192
			key:     HexToBytes("8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B"),
			iv:      HexToBytes("000102030405060708090A0B0C0D0E0F"),
			encrypt: true,
			in:      HexToBytes("6BC1BEE22E409F96E93D7E117393172A"),
			out:     HexToBytes("4F021DB243BC633D7178183A9FA071E8"),
		},
		{
			alg:     AES, // 256
			key:     HexToBytes("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4"),
			iv:      HexToBytes("000102030405060708090A0B0C0D0E0F"),
			encrypt: true,
			in:      HexToBytes("6BC1BEE22E409F96E93D7E117393172A"),
			out:     HexToBytes("F58C4C04D6E5F1BA779EABFB5F7BFBD6"),
		},
	}
	for _, tc := range testCases {
		var err error
		var cipher cipher.Block

		cipher, err = GetCipherForKey(tc.alg, tc.key)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		act := CryptCBC(cipher, tc.iv, tc.in, tc.encrypt)

		if !bytes.Equal(act, tc.out) {
			t.Errorf("CryptCBC failed (Exp:%x) (Act:%x)", tc.out, act)
		}
	}

}

func TestCryptoPad(t *testing.T) {
	testCases := []struct {
		data      []byte
		blockSize int
		exp       []byte
	}{
		{
			data:      HexToBytes("1234567880"),
			blockSize: 8,
			exp:       HexToBytes("1234567880800000"),
		},
		{
			data:      HexToBytes("1234"),
			blockSize: 8,
			exp:       HexToBytes("1234800000000000"),
		},
		{
			data:      HexToBytes(""),
			blockSize: 8,
			exp:       HexToBytes("8000000000000000"),
		},
		{
			data:      HexToBytes("1234567890ABCDEF"),
			blockSize: 8,
			exp:       HexToBytes("1234567890ABCDEF8000000000000000"),
		},
	}
	for _, tc := range testCases {
		out := ISO9797Method2Pad(tc.data, tc.blockSize)

		if !bytes.Equal(tc.exp, out) {
			t.Errorf("Pad failed (Exp:%x) (Act:%x)", tc.exp, out)
		}
	}
}

func TestCryptoUnpad(t *testing.T) {
	testCases := []struct {
		in  []byte
		exp []byte
	}{
		{
			in:  HexToBytes("123456788080"),
			exp: HexToBytes("1234567880"),
		},
		{
			in:  HexToBytes("12348000000000"),
			exp: HexToBytes("1234"),
		},
		{
			in:  HexToBytes("800000"),
			exp: HexToBytes(""),
		},
	}
	for _, tc := range testCases {
		actBytes := ISO9797Method2Unpad(tc.in)

		if !bytes.Equal(tc.exp, actBytes) {
			t.Errorf("Unpad failed (Exp:%x) (Act:%x)", tc.exp, actBytes)
		}
	}
}

func TestCryptoMAC(t *testing.T) {
	// TODO
}

func TestCryptoSHA1(t *testing.T) {
	inp := []byte{0x23, 0x9A, 0xB9, 0xCB, 0x28, 0x2D, 0xAF, 0x66, 0x23, 0x1D, 0xC5, 0xA4, 0xDF, 0x6B, 0xFB, 0xAE, 0x00, 0x00, 0x00, 0x02}
	exp := []byte{0x78, 0x62, 0xD9, 0xEC, 0xE0, 0x3C, 0x1B, 0xCD, 0x4D, 0x77, 0x08, 0x9D, 0xCF, 0x13, 0x14, 0x42, 0x81, 0x4E, 0xA7, 0x0A}

	out := CryptoHash(SHA1, inp)

	if !bytes.Equal(exp, out) {
		t.Errorf("SHA1 failed")
	}
}

func TestCryptoHash(t *testing.T) {
	testCases := []struct {
		alg     HashAlg
		data    []byte
		expHash []byte
	}{
		{
			alg:     SHA1,
			data:    HexToBytes("616263"),
			expHash: HexToBytes("a9993e364706816aba3e25717850c26c9cd0d89d"),
		},
		{
			alg:     SHA256,
			data:    HexToBytes(""),
			expHash: HexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		},
		{
			alg:     SHA256,
			data:    HexToBytes("de188941a3375d3a8a061e67576e926d"),
			expHash: HexToBytes("067c531269735ca7f541fdaca8f0dc76305d3cada140f89372a410fe5eff6e4d"),
		},
	}
	for _, tc := range testCases {
		actHash := CryptoHash(tc.alg, tc.data)

		if !bytes.Equal(tc.expHash, actHash) {
			t.Errorf("CryptoHash failed (Exp:%x) (Act:%x)", tc.expHash, actHash)
		}
	}

}

func TestDesAdjustParity(t *testing.T) {
	inp := []byte{0xAB, 0x94, 0xFC, 0xED, 0xF2, 0x66, 0x4E, 0xDF, 0xB9, 0xB2, 0x91, 0xF8, 0x5D, 0x7F, 0x77, 0xF2, 0x78, 0x62, 0xD9, 0xEC, 0xE0, 0x3C, 0x1B, 0xCD, 0x4D, 0x77, 0x08, 0x9D, 0xCF, 0x13, 0x14, 0x42}
	exp := []byte{0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F, 0x76, 0xF2, 0x79, 0x62, 0xD9, 0xEC, 0xE0, 0x3D, 0x1A, 0xCD, 0x4C, 0x76, 0x08, 0x9D, 0xCE, 0x13, 0x15, 0x43}

	out := DesKeyAdjustParity(inp)

	if !bytes.Equal(exp, out) {
		t.Errorf("Parity test failed")
	}
}

func TestRandomBytes(t *testing.T) {
	out := RandomBytes(21)

	if len(out) != 21 {
		t.Errorf("Length mismatch")
	}
}

func TestKeyGeneratorEc(t *testing.T) {
	pri, pub := KeyGeneratorEc(brainpool.P512r1())

	// TODO - not a very good test.. better to do sign/verify sequence.. instead of just testing key lengths
	if (len(pri) > 512/8) ||
		(len(pub.x.Bytes()) > 512/8) ||
		(len(pub.y.Bytes()) > 512/8) {
		t.Errorf("Bad key length (pri:%d, pub.x:%d, pub.y:%d)", len(pri), len(pub.x.Bytes()), len(pub.y.Bytes()))
	}
}

func TestX962EcPointEncoding(t *testing.T) {
	testCases := []struct {
		ec       elliptic.Curve
		x        []byte
		y        []byte
		expBytes []byte
	}{
		{
			ec:       brainpool.P256r1(),
			x:        HexToBytes("7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E"),
			y:        HexToBytes("544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D"),
			expBytes: HexToBytes("047ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D"),
		},
	}
	for _, tc := range testCases {
		var point EC_POINT
		point.x = new(big.Int).SetBytes(tc.x)
		point.y = new(big.Int).SetBytes(tc.y)

		actBytes := EncodeX962EcPoint(tc.ec, &point)

		if !bytes.Equal(tc.expBytes, actBytes) {
			t.Errorf("X962 encoding failed (Exp:%x) (Act:%x)", tc.expBytes, actBytes)
		}

		decodedPoint := DecodeX962EcPoint(tc.ec, actBytes)

		if point.x.Cmp(decodedPoint.x) != 0 || point.y.Cmp(decodedPoint.y) != 0 {
			t.Errorf("X962 decoding failed")
		}
	}
}

func TestGetCipherForKey(t *testing.T) {

	cipher, err := GetCipherForKey(-1, HexToBytes("0123456789ABCDEF"))

	if err == nil {
		t.Errorf("Error expected")
	}

	if cipher != nil {
		t.Errorf("Cipher not expected for error case")
	}
}
