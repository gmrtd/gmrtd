package cryptoutils

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
	"github.com/osanderson/brainpool"
)

func TestEcPointEqual(t *testing.T) {
	testCases := []struct {
		ecPoint1 EcPoint
		ecPoint2 EcPoint
		equals   bool
	}{
		{
			ecPoint1: EcPoint{X: big.NewInt(12345), Y: big.NewInt(67890)},
			ecPoint2: EcPoint{X: big.NewInt(12345), Y: big.NewInt(67890)},
			equals:   true,
		},
		{
			// X differs
			ecPoint1: EcPoint{X: big.NewInt(12345), Y: big.NewInt(67890)},
			ecPoint2: EcPoint{X: big.NewInt(12346), Y: big.NewInt(67890)},
			equals:   false,
		},
		{
			// Y differs
			ecPoint1: EcPoint{X: big.NewInt(12345), Y: big.NewInt(67890)},
			ecPoint2: EcPoint{X: big.NewInt(12345), Y: big.NewInt(67891)},
			equals:   false,
		},
		{
			// X+Y differs
			ecPoint1: EcPoint{X: big.NewInt(12345), Y: big.NewInt(67890)},
			ecPoint2: EcPoint{X: big.NewInt(12346), Y: big.NewInt(67891)},
			equals:   false,
		},
	}
	for _, tc := range testCases {
		actEquals := tc.ecPoint1.Equal(tc.ecPoint2)

		if actEquals != tc.equals {
			t.Errorf("Unexpected EcPoint.Equal result (exp:%t, act:%t)", tc.equals, actEquals)
		}
	}
}

func TestTDesKey(t *testing.T) {
	testCases := []struct {
		keyIn  []byte
		keyOut []byte
	}{
		{
			keyIn:  []byte{0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF},
			keyOut: []byte{0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF},
		},
		{
			keyIn:  []byte{0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F, 0x76, 0xF2},
			keyOut: []byte{0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F, 0x76, 0xF2, 0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF},
		},
		{
			keyIn:  []byte{0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xDF, 0xDF, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xEC, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF},
			keyOut: []byte{0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xDF, 0xDF, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xEC, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF},
		},
	}
	for _, tc := range testCases {
		out, err := tdesKey(tc.keyIn)

		if err != nil {
			t.Errorf("Unexpect error: %s", err)
		}

		if !bytes.Equal(tc.keyOut, out) {
			t.Errorf("TDes key expansion failed")
		}
	}
}

// cipher/key combinations:
// - DES: 8 bytes
// - TDES: 8/16/24 bytes
// - AES: 16/24/32 bytes
func TestGetCipherForKey(t *testing.T) {
	testCases := []struct {
		alg BlockCipherAlg
		key []byte
	}{
		// NB for DES/TDES we make NO attempt to pass in keys with valid parity bits
		//    - if the underlying crypto library becomes stricter then these tests may fail
		{
			// DES - 8 byte key
			alg: DES,
			key: utils.HexToBytes("0123456789ABCDEF"),
		},
		{
			// TDES - 8 byte key
			alg: TDES,
			key: utils.HexToBytes("0123456789ABCDEF"),
		},
		{
			// TDES - 16 byte key
			alg: TDES,
			key: utils.HexToBytes("000102030405060708090A0B0C0D0E0F"),
		},
		{
			// TDES - 24 byte key
			alg: TDES,
			key: utils.HexToBytes("000102030405060708090A0B0C0D0E0F1011121314151617"),
		},
		{
			// AES - 16 byte key
			alg: AES,
			key: utils.HexToBytes("000102030405060708090A0B0C0D0E0F"),
		},
		{
			// AES - 24 byte key
			alg: AES,
			key: utils.HexToBytes("000102030405060708090A0B0C0D0E0F1011121314151617"),
		},
		{
			// AES - 32 byte key
			alg: AES,
			key: utils.HexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
		},
	}
	for _, tc := range testCases {
		cipher, err := GetCipherForKey(tc.alg, tc.key)

		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		} else if cipher == nil {
			t.Errorf("Cipher expected")
		}
	}
}

func TestGetCipherForKeyError(t *testing.T) {
	testCases := []struct {
		alg BlockCipherAlg
		key []byte
	}{
		{
			// unknown algorithm
			alg: -1,
			key: utils.HexToBytes("0123456789ABCDEF"),
		},
		{
			// DES - bad key length (7 bytes)
			alg: DES,
			key: utils.HexToBytes("0123456789ABCD"),
		},
		{
			// TDES - bad key length (7 bytes)
			alg: TDES,
			key: utils.HexToBytes("0123456789ABCD"),
		},
		{
			// TDES - bad key length (15 bytes)
			alg: TDES,
			key: utils.HexToBytes("000102030405060708090A0B0C0D0E"),
		},
		{
			// TDES - bad key length (25 bytes)
			alg: TDES,
			key: utils.HexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718"),
		},
		{
			// AES - bad key length (25 bytes)
			alg: AES,
			key: utils.HexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718"),
		},
	}
	for _, tc := range testCases {
		cipher, err := GetCipherForKey(tc.alg, tc.key)

		if err == nil {
			t.Errorf("Error expected")
		} else if cipher != nil {
			t.Errorf("Cipher not expected for error case")
		}
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
			key:     utils.HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F2"),
			iv:      make([]byte, 8),
			encrypt: true,
			in:      utils.HexToBytes("781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B"),
			out:     utils.HexToBytes("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2"),
		},
		{
			alg:     TDES, // double-key
			key:     utils.HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F2"),
			iv:      make([]byte, 8),
			encrypt: false,
			in:      utils.HexToBytes("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2"),
			out:     utils.HexToBytes("781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B"),
		},
		{
			alg:     AES, // 128
			key:     utils.HexToBytes("2B7E151628AED2A6ABF7158809CF4F3C"),
			iv:      utils.HexToBytes("000102030405060708090A0B0C0D0E0F"),
			encrypt: true,
			in:      utils.HexToBytes("6BC1BEE22E409F96E93D7E117393172A"),
			out:     utils.HexToBytes("7649ABAC8119B246CEE98E9B12E9197D"),
		},
		{
			alg:     AES, // 192
			key:     utils.HexToBytes("8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B"),
			iv:      utils.HexToBytes("000102030405060708090A0B0C0D0E0F"),
			encrypt: true,
			in:      utils.HexToBytes("6BC1BEE22E409F96E93D7E117393172A"),
			out:     utils.HexToBytes("4F021DB243BC633D7178183A9FA071E8"),
		},
		{
			alg:     AES, // 256
			key:     utils.HexToBytes("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4"),
			iv:      utils.HexToBytes("000102030405060708090A0B0C0D0E0F"),
			encrypt: true,
			in:      utils.HexToBytes("6BC1BEE22E409F96E93D7E117393172A"),
			out:     utils.HexToBytes("F58C4C04D6E5F1BA779EABFB5F7BFBD6"),
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

func TestCryptCBCIVLengthErr(t *testing.T) {
	// IV length must match the block size, which for TDES is 8 bytes
	// - we trigger panic by providing a 7 byte IV instead

	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	var tdesKey []byte = utils.HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F2")

	var err error
	var cipher cipher.Block

	cipher, err = GetCipherForKey(TDES, tdesKey)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	var iv []byte = utils.HexToBytes("0123456789abcd")
	var data []byte = utils.HexToBytes("0000000000000000")

	_ = CryptCBC(cipher, iv, data, true)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestCryptCBCDataLengthErr(t *testing.T) {
	// data length must be an exact multiple of the block size, which for TDES is 8 bytes
	// - we trigger panic by providing a 17 bytes of data

	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	var tdesKey []byte = utils.HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F2")

	var err error
	var cipher cipher.Block

	cipher, err = GetCipherForKey(TDES, tdesKey)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	var iv []byte = utils.HexToBytes("0123456789abcdef")
	var data []byte = utils.HexToBytes("0000000000000000000000000000000000")

	_ = CryptCBC(cipher, iv, data, true)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestCryptoHashOidToAlgErr(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	// NB error as we're using an OID which clearly doesn't map to a hash (i.e. EmailAddress)
	_ = CryptoHashByOid(oid.OidEmailAddress, []byte{0x12, 0x34})

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestCryptoHash(t *testing.T) {
	/*
	 * Performs combined testing for both 'CryptoHash' and 'CryptoHashByOid'
	 */

	// test vectors from:
	//		https://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
	testCases := []struct {
		alg     crypto.Hash
		algOid  asn1.ObjectIdentifier
		data    []byte
		expHash []byte
	}{
		{
			alg:     crypto.MD5,
			algOid:  oid.OidHashAlgorithmMD5,
			data:    []byte("The quick brown fox jumps over the lazy dog"),
			expHash: utils.HexToBytes("9e107d9d372bb6826bd81d3542a419d6"),
		},
		{
			alg:     crypto.SHA1,
			algOid:  oid.OidHashAlgorithmSHA1,
			data:    []byte("The quick brown fox jumps over the lazy dog"),
			expHash: utils.HexToBytes("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
		},
		{
			alg:     crypto.SHA256,
			algOid:  oid.OidHashAlgorithmSHA256,
			data:    []byte("The quick brown fox jumps over the lazy dog"),
			expHash: utils.HexToBytes("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),
		},
		{
			alg:     crypto.SHA384,
			algOid:  oid.OidHashAlgorithmSHA384,
			data:    []byte("The quick brown fox jumps over the lazy dog"),
			expHash: utils.HexToBytes("ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"),
		},
		{
			alg:     crypto.SHA512,
			algOid:  oid.OidHashAlgorithmSHA512,
			data:    []byte("The quick brown fox jumps over the lazy dog"),
			expHash: utils.HexToBytes("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"),
		},
		{
			alg:     crypto.SHA224,
			algOid:  oid.OidHashAlgorithmSHA224,
			data:    []byte("The quick brown fox jumps over the lazy dog"),
			expHash: utils.HexToBytes("730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525"),
		},
	}
	for _, tc := range testCases {
		/*
		* Test CryptoHash
		 */
		{
			actHash := CryptoHash(tc.alg, tc.data)

			if !bytes.Equal(tc.expHash, actHash) {
				t.Errorf("CryptoHash failed for Alg:%01d (Exp:%x) (Act:%x)", tc.alg, tc.expHash, actHash)
			}
		}

		/*
		* Test CryptoHashByOid
		 */
		{
			actHash := CryptoHashByOid(tc.algOid, tc.data)

			if !bytes.Equal(tc.expHash, actHash) {
				t.Errorf("CryptoHashByOid failed for OID:%s (Exp:%x) (Act:%x)", tc.algOid.String(), tc.expHash, actHash)
			}
		}
	}
}

func TestCryptoHashErr(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	// NB error as we're using an algorithm (99) that isn't valid
	_ = CryptoHash(99, []byte{0x12, 0x34})

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestCryptoHashDigestSize(t *testing.T) {
	testCases := []struct {
		alg     crypto.Hash
		expSize int
	}{
		{
			alg:     crypto.MD5,
			expSize: 16,
		},
		{
			alg:     crypto.SHA1,
			expSize: 20,
		},
		{
			alg:     crypto.SHA256,
			expSize: 32,
		},
		{
			alg:     crypto.SHA384,
			expSize: 48,
		},
		{
			alg:     crypto.SHA512,
			expSize: 64,
		},
		{
			alg:     crypto.SHA224,
			expSize: 28,
		},
	}
	for _, tc := range testCases {
		actSize := CryptoHashDigestSize(tc.alg)

		if tc.expSize != actSize {
			t.Errorf("TestCryptoHashDigestSize unexpected size (exp:%01d, act:%01d)", tc.expSize, actSize)
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
	keypair := KeyGeneratorEc(brainpool.P512r1())

	// TODO - not a very good test.. better to do sign/verify sequence.. instead of just testing key lengths
	if (len(keypair.Pri) > 512/8) ||
		(len(keypair.Pub.X.Bytes()) > 512/8) ||
		(len(keypair.Pub.Y.Bytes()) > 512/8) {
		t.Errorf("Bad key length (pri:%d, pub.x:%d, pub.y:%d)", len(keypair.Pri), len(keypair.Pub.X.Bytes()), len(keypair.Pub.Y.Bytes()))
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
			x:        utils.HexToBytes("7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E"),
			y:        utils.HexToBytes("544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D"),
			expBytes: utils.HexToBytes("047ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D"),
		},
	}
	for _, tc := range testCases {
		var point EcPoint
		point.X = new(big.Int).SetBytes(tc.x)
		point.Y = new(big.Int).SetBytes(tc.y)

		actBytes := EncodeX962EcPoint(tc.ec, &point)

		if !bytes.Equal(tc.expBytes, actBytes) {
			t.Errorf("X962 encoding failed (Exp:%x) (Act:%x)", tc.expBytes, actBytes)
		}

		decodedPoint := DecodeX962EcPoint(tc.ec, actBytes)

		if point.X.Cmp(decodedPoint.X) != 0 || point.Y.Cmp(decodedPoint.Y) != 0 {
			t.Errorf("X962 decoding failed")
		}
	}
}

func TestDoEcDh(t *testing.T) {
	testCases := []struct {
		ec         elliptic.Curve
		privateKey []byte
		publicKey  *EcPoint
		expected   *EcPoint
	}{
		{
			ec:         brainpool.P256r1(),
			privateKey: utils.HexToBytes("80ebafc8a51becd4d90bb640ee38c9fd5c12748d28aaa37096b98c4533c4f5f5"),
			publicKey:  &EcPoint{X: new(big.Int).SetBytes(utils.HexToBytes("1983917269ac877c0b61544c2c022000d2a5aba723e2d80141e648b40911dc34")), Y: new(big.Int).SetBytes(utils.HexToBytes("59761f27480e4b57181a53d8fe1190ea86c939ac14363178caffc621f0f905c3"))},
			expected:   &EcPoint{X: new(big.Int).SetBytes(utils.HexToBytes("0346c3ca1a64f5cd62b61d7591020283089496a53db2bb5e900d386e92f4686d")), Y: new(big.Int).SetBytes(utils.HexToBytes("233c7356c897aa066ea4e6df7ec3224ab6f771c0ca8efc8f5332138700047516"))},
		},
		{
			ec:         brainpool.P256r1(),
			privateKey: utils.HexToBytes("7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99"),
			publicKey:  &EcPoint{X: new(big.Int).SetBytes(utils.HexToBytes("824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57")), Y: new(big.Int).SetBytes(utils.HexToBytes("30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54"))},
			expected:   &EcPoint{X: new(big.Int).SetBytes(utils.HexToBytes("60332EF2450B5D247EF6D3868397D398852ED6E8CAF6FFEEF6BF85CA57057FD5")), Y: new(big.Int).SetBytes(utils.HexToBytes("0840CA7415BAF3E43BD414D35AA4608B93A2CAF3A4E3EA4E82C9C13D03EB7181"))},
		},
	}
	for _, tc := range testCases {

		var actual *EcPoint = DoEcDh(tc.privateKey, tc.publicKey, tc.ec)

		if !actual.Equal(*tc.expected) {
			t.Errorf("ECDH error (Exp:%s) (Act:%s)", tc.expected, actual)
		}
	}
}

func TestRsaDecryptWithPublicKey(t *testing.T) {
	testCases := []struct {
		ciphertext   []byte
		publicKey    RsaPublicKey
		expPlaintext []byte
	}{
		{
			ciphertext:   utils.HexToBytes("474256306840c0ab1b63c10e1c26bdfef4a0dd843920283cc4e6e70a60f2bd25dc7725f9677bc1cde66379dc28b38e8490f33afb2d10f9980c44c0bfc175d2b6684218f535c92fdd3e18db770a9ccbf91db3c7f0138e6d9e94b9bc8371761e3abed5e5e9b260279cfb238b58ae0d6a01da51c74c2a3ecd62c448bd9f20127f7384587287fa971204234e55b1a856c3e5aaaa620bb799a68fbae08ee132bb61683eba9b0b40dc1e54641cad975b16991cab50af82e3f3985afd19e7427a125f5b4b9878b12a5d2e01c7eedca3bb41c6fc05dccd818bce379d04b1f2f5d43487d3"),
			publicKey:    RsaPublicKey{E: 65537, N: new(big.Int).SetBytes(utils.HexToBytes("bb8f93f4dc95e205cda17c6927ab1e365b13065d03cd12e0fce95d96840529453202f56cc4c13f77cd062930c8bc89a2873b257045c286e601cf3c09323a53103314902804aa10a314628ce222206a8866946a36b442041bb54ac81e6855dd1d6e16101833d65a191c20ac8b33b8a1a32920f46043f8031cf2bc17417030865fc5be5a39dee423bcba3ca8177168eb23cfe01ba43ec87711b1cfff85db46f300dd8ae317b50d543b573e119e23af7070d0b2fed6a3b2313a5ec02a531aaed1741f4390d1013e2a0f081eac5dc8b0a1b2c6bdb1206f08d30e3643e1e5bdf53611"))},
			expPlaintext: utils.HexToBytes("6ad982bdf542cdc574053dc2f30e425e378f9a907187261574a1b046ac1831fae9f8235beb20272e867486549efcfc37ba618b89594a879a46d43960469d910e3b11b5d062a6615c82b20a8c424e715109fe330a874629e731b19d267cbbc84aeed64e6a477a2cb416054a1f3d706c0212fb6d2c82014fd7fd827c93380a4f3f67901d55a9842c13613414a8933530888608e02109ba6b3270cbe9f9885af136a5ed82900faff4b7780454f5905833511bafa69f51a5365c26ee7cbb7b39750c1a52410f3e339490d5a7a8de4d27eebd37c6810d8d1f7b854d3d891015dc34cc"),
		},
		{
			ciphertext:   utils.HexToBytes("3593195e884103297dfe628dc10230063bcef6edf13369499ece259ae1f70c1a59cce9f1b444b2f9d12c7c2c877d7be1b81b61a36827862a596853412d1849ca36e6e5de095c7a8d505784955ad321cbccbe7a6f5172bc26e32c9f01c8c5d7cf38cf33aa53a4e174cbc86d5e18a9312a2d5377027a274d002a5ab4f5fedfb3cc5af9eb4b7d6158a8bef16a627be88058342683699e72b3e2f35f5a7e41451d458ae92a6d26da693df4bd4d9d8a498a07323934fb50c9b9bcca013e98e872937ae3875fba6665e3b92cf22f33a1087c5cb655724a1fff183f4be5980e3bc19a46f9656ef81ad2ed6ee3f0e74dc91ec71c1a82fc1db4e1ed8dd5eef9a6361cb849"),
			publicKey:    RsaPublicKey{E: 65537, N: new(big.Int).SetBytes(utils.HexToBytes("c0287bde6240e37aec9741d64947758b2bbbcd58a87429442fa6c14ee6481f94d2a221352e663d4c1eaec896f18c235160d47b548e5b445948c976614d263c6568ea9d08ea504fd930d9775d9ce82a3a834c4efde2d6bab04c499045a3c25dcf29c8e9ba4c58958300c687323066a2ad9ea54c8a23d4aa75dbcaf0ae5cfc8176a94b891ad97c328ca03186c1151d4eb3dcbbcabef8a9f77f50959bfe30891605a7725bf6de59240dd1818c6cbd4b71c9a41c8d0a8c77eca1559b3ca124a09f75bb44178a17e29d5c871da0dc5a50dad2873321fdefe8374abfe41fb0fc2cc2cb4f255aa5fb3d614b18fee3fe3346c8e0f9f73de66348e011a17be8851c59d325"))},
			expPlaintext: utils.HexToBytes("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003031300d06096086480165030402010500042033a080adf3754860918c27d6688f6b712ab1672267cffd8831a9aabe620bd86b"),
		},
		{
			ciphertext:   utils.HexToBytes("3862f39e9140bde1296f4d4a2b007c03f79d8104d931f85e0f1b7ed54ed2c12c2c548bd167b3ca03bf72e82e28b380b0199d30f2bef17543892e2a2c9fa17cfcbd1a2db9900c3052d8c3ab138d870014ecb7efa4a03775f873efb96e995871589981b0a6bf06a2897bc41da92a4d88e3e071cd234aad569e0ebfdcee59f065724f3b7087ec328a6dc17538794b79343a194fb91966f4f615f66c2e5b5605803883a87637323e5e9d10d0497e9184c80a6d7cfad0d77fea773b487b7a44115650b73241f5af1ae7eb7d90882c65febdd9ce183c93b6589f521a948c5e3994bfe09266c95e0bd9dde4b297b2613b6ff75d52087c112aa8291c3d2ad7f3e5a39233"),
			publicKey:    RsaPublicKey{E: 65537, N: new(big.Int).SetBytes(utils.HexToBytes("a5a5964e7b8e9d8c623bda63760d1406374026d81f21e34f6b06c6f47774d9df7a0e9d7979ba2c72d4eacc45d1a58a4c5fc20bad8ae23fdc4024c8e53a8acdc2b083ec55b63d44d557e048ed1b843cd2b99c147b350c6fb9b67fd02076bec134c785f4de58a1aa137196d6fb7eefd47a03f25996841345a4daab7754b047dab57e5786d54de5cde5faf553f44de67069f84c2c38e57d0fd13255c814629bafb2c8932ec8e7029d9ec59d640982f89545e30f22036e0bc58e3e8d4ac8e43c3429bdd9bd545ce6ad1045b28d839169060d93af72f59bbfa0687c8a90d12bad51481cc991df9855dd7aa8fa31250b39ab52563b211362f539a47c167ca496fcbd51"))},
			expPlaintext: utils.HexToBytes("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003031300d06096086480165030402010500042057ba4d1675bf2e2d4ac2096c73e724e9b8e81806210da62617b3c87c585f1125"),
		},
	}
	for _, tc := range testCases {
		var plaintext []byte

		plaintext = RsaDecryptWithPublicKey(tc.ciphertext, tc.publicKey)

		if !bytes.Equal(plaintext, tc.expPlaintext) {
			t.Errorf("Decryption error (Exp:%x) (Act:%x)", tc.expPlaintext, plaintext)
		}
	}
}

func TestRsaDecryptWithPublicKeyErr(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	var data []byte = []byte{}
	var rsaPubKey RsaPublicKey = RsaPublicKey{E: 65537, N: new(big.Int).SetBytes(utils.HexToBytes("a5a5964e7b8e9d8c623bda63760d1406374026d81f21e34f6b06c6f47774d9df7a0e9d7979ba2c72d4eacc45d1a58a4c5fc20bad8ae23fdc4024c8e53a8acdc2b083ec55b63d44d557e048ed1b843cd2b99c147b350c6fb9b67fd02076bec134c785f4de58a1aa137196d6fb7eefd47a03f25996841345a4daab7754b047dab57e5786d54de5cde5faf553f44de67069f84c2c38e57d0fd13255c814629bafb2c8932ec8e7029d9ec59d640982f89545e30f22036e0bc58e3e8d4ac8e43c3429bdd9bd545ce6ad1045b28d839169060d93af72f59bbfa0687c8a90d12bad51481cc991df9855dd7aa8fa31250b39ab52563b211362f539a47c167ca496fcbd51"))}

	// NB will fail due to zero-length data
	_ = RsaDecryptWithPublicKey(data, rsaPubKey)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestEllipticP192WithEcDh(t *testing.T) {
	/*
	* performs a basic test on P192 by verifying the ECDH works
	 */
	var p192 elliptic.Curve = EllipticP192()

	var keyPair1 EcKeypair = KeyGeneratorEc(p192)
	var keyPair2 EcKeypair = KeyGeneratorEc(p192)

	var ecPoint1 *EcPoint = DoEcDh(keyPair1.Pri, keyPair2.Pub, p192)
	var ecPoint2 *EcPoint = DoEcDh(keyPair2.Pri, keyPair1.Pub, p192)

	if !ecPoint1.Equal(*ecPoint2) {
		t.Errorf("P192-with-ECDH EcPoint mismatch following ECDH (ecPoint1:%s, ecPoint2:%s)", ecPoint1.String(), ecPoint2.String())
	}
}
