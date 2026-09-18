package activeauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/utils"
)

// real RSA DG15 + RND.IFD + valid decrypted-signature ('f') triple, reused from
// TestDoActiveAuth (its result.Evidence.Signature is exactly the intAuthRspBytes
// fuzzed here).
var fuzzRsaDg15Bytes = utils.HexToBytes("6F8201023081FF300D06092A864886F70D01010105000381ED003081E90281E100BB8F93F4DC95E205CDA17C6927AB1E365B13065D03CD12E0FCE95D96840529453202F56CC4C13F77CD062930C8BC89A2873B257045C286E601CF3C09323A53103314902804AA10A314628CE222206A8866946A36B442041BB54AC81E6855DD1D6E16101833D65A191C20AC8B33B8A1A32920F46043F8031CF2BC17417030865FC5BE5A39DEE423BCBA3CA8177168EB23CFE01BA43EC87711B1CFFF85DB46F300DD8AE317B50D543B573E119E23AF7070D0B2FED6A3B2313A5EC02A531AAED1741F4390D1013E2A0F081EAC5DC8B0A1B2C6BDB1206F08D30E3643E1E5BDF536110203010001")

var fuzzRsaDg15, _ = document.NewDG15(fuzzRsaDg15Bytes)

var fuzzRsaRndIfd = utils.HexToBytes("96302b0f3d7e7864")

var fuzzRsaValidSig = utils.HexToBytes("474256306840c0ab1b63c10e1c26bdfef4a0dd843920283cc4e6e70a60f2bd25dc7725f9677bc1cde66379dc28b38e8490f33afb2d10f9980c44c0bfc175d2b6684218f535c92fdd3e18db770a9ccbf91db3c7f0138e6d9e94b9bc8371761e3abed5e5e9b260279cfb238b58ae0d6a01da51c74c2a3ecd62c448bd9f20127f7384587287fa971204234e55b1a856c3e5aaaa620bb799a68fbae08ee132bb61683eba9b0b40dc1e54641cad975b16991cab50af82e3f3985afd19e7427a125f5b4b9878b12a5d2e01c7eedca3bb41c6fc05dccd818bce379d04b1f2f5d43487d3")

// fresh EC (P-256) DG15 + RND.IFD + valid signature (plain r||s and DER forms),
// generated once at fuzz setup time — this repo's own tests only generate ephemeral
// EC keys per run (see TestEcdsaValidateActiveAuthSignatureAllCurves), so there's no
// fixed real sample to reuse; this mirrors that same approach for a stable fuzz seed.
var fuzzEcDg15, fuzzEcRndIfd, fuzzEcPlainSig, fuzzEcDerSig = mustBuildEcdsaFuzzSeed()

func mustBuildEcdsaFuzzSeed() (dg15 *document.DG15, rndIfd, plainSig, derSig []byte) {
	curve := elliptic.P256()

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	dg15Bytes, err := makeDG15FromECPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}

	dg15, err = document.NewDG15(dg15Bytes)
	if err != nil {
		panic(err)
	}

	rndIfd = cryptoutils.RandomBytes(8)
	hashAlg := cryptoutils.CryptoHashFromEcPubKey(&priv.PublicKey)
	hash := cryptoutils.CryptoHash(hashAlg, rndIfd)

	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	if err != nil {
		panic(err)
	}

	plainSig = concatRSFixed(curve, r, s)

	derSig, err = encodeDERSignature(r, s)
	if err != nil {
		panic(err)
	}

	return dg15, rndIfd, plainSig, derSig
}

// FuzzValidateActiveAuthSignatureRsa fuzzes the top-level AA verifier with a fixed
// real RSA DG15/nonce and a fuzzed intAuthRspBytes (the chip's INTERNAL AUTHENTICATE
// response). RsaDecryptWithPublicKey is a public-key (no secret) operation, so unlike
// a MAC-gated protocol, mutation fuzzing here genuinely reaches decodeF/hash-compare.
func FuzzValidateActiveAuthSignatureRsa(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(fuzzRsaValidSig)

	f.Fuzz(func(t *testing.T, intAuthRspBytes []byte) {
		_, _ = ValidateActiveAuthSignature(fuzzRsaDg15, intAuthRspBytes, fuzzRsaRndIfd)
	})
}

// FuzzValidateActiveAuthSignatureEcdsa is the ECDSA-key counterpart, exercising
// parseEcdsaSignaturePlain/parseEcdsaSignatureDER via the real call path.
func FuzzValidateActiveAuthSignatureEcdsa(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(fuzzEcPlainSig)
	f.Add(fuzzEcDerSig)

	f.Fuzz(func(t *testing.T, intAuthRspBytes []byte) {
		_, _ = ValidateActiveAuthSignature(fuzzEcDg15, intAuthRspBytes, fuzzEcRndIfd)
	})
}

func FuzzParseEcdsaSignaturePlain(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(fuzzEcPlainSig)
	f.Add([]byte{0, 0}) // even length, but zero R/S (not well-formed)

	f.Fuzz(func(t *testing.T, sigBytes []byte) {
		_, _ = parseEcdsaSignaturePlain(sigBytes)
	})
}

func FuzzParseEcdsaSignatureDER(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(fuzzEcDerSig)
	f.Add([]byte{0x30, 0x05, 0x01, 0x02, 0x03}) // invalid DER

	f.Fuzz(func(t *testing.T, sigBytes []byte) {
		_, _ = parseEcdsaSignatureDER(sigBytes)
	})
}

func FuzzDecodeF(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(utils.HexToBytes("6A1234567890ABCDEF1234567890ABCDEF11223344e9b287952a913cc5b60ff74ecfc87e40e81563b1BC"))                                                                                           // SHA-1
	f.Add(utils.HexToBytes("6A1234567890ABCDEF1234567890ABCDEF11223344aefc05e88f48eb88d367ba3dacb7d6a8543ec02bd315e47ddbe2045d38CC"))                                                                         // SHA-224
	f.Add(utils.HexToBytes("6A1234567890ABCDEF1234567890ABCDEF11223344783980d44fd3a80f0e4210eb9c73ea399932062d465438f8e1ff13377de8308934CC"))                                                                 // SHA-256
	f.Add(utils.HexToBytes("6A1234567890ABCDEF1234567890ABCDEF112233448e0873b0baf595a777b497779981bd94dda3a81fd61cf2d526ab490f2d6cbcecc6eab5804df4e0a70169d4d0d6c07e7536CC"))                                 // SHA-384
	f.Add(utils.HexToBytes("6A1234567890ABCDEF1234567890ABCDEF11223344968304e09f0c0ec86be4ade4b82d97d04283e3652b61193856c9ede1dac8962b3da9580fd77e9f9ef18a24c517d8d3b05f4eeb177e990ae1e80895c8bb28f51635CC")) // SHA-512

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = decodeF(data)
	})
}
