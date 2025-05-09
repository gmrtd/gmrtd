package cms

import (
	"encoding/asn1"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

func TestVerifySignatureEcdsa(t *testing.T) {
	testCases := []struct {
		data         []byte
		digestAlg    asn1.ObjectIdentifier
		signatureAlg asn1.ObjectIdentifier
		keyDer       []byte
		signature    []byte
	}{
		// NB unable to find test-vector for brainpool-192
		{
			// brainpool224 / sha-224
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_brainpoolP224r1_sha224_test.json (tcId:4)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA224,
			signatureAlg: oid.OidEcdsaWithSHA224,
			keyDer:       utils.HexToBytes("3052301406072a8648ce3d020106092b2403030208010105033a0004572eab7376d052dfc40923db25342ea9cbfce4b8581e104a4c8f37c94a700ec5dc05a481b2b695320c6f1ad2dd8628633cdb75a91245c265"),
			signature:    utils.HexToBytes("303e021d00cb68ac9765c7641785df237e9951e1429581879af2631460048961d3021d00c424bc85ebd52fa505423a442a8443238658ca3b7c39bace3f3d5110"),
		},
		{
			// brainpool256 / sha-256
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_brainpoolP256r1_sha256_test.json (tcId:2)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA256,
			signatureAlg: oid.OidEcdsaWithSHA256,
			keyDer:       utils.HexToBytes("305a301406072a8648ce3d020106092b240303020801010703420004019a2d9637743a63ddaefdbca0ee229a163b809b9b145e5313bbeb8defeab9d6548caf89bf5ba49499404145651234336401b9b2843a579ed152e090f11b9e59"),
			signature:    utils.HexToBytes("304402200a5f8c70ba2d0842d5d0f841f160ad15195769a8159bfe692634d73d469d111f0220678cd260f4aeb211a781388fdd48478007cf43d32b736de019916ce1c0737c39"),
		},
		{
			// brainpool320 / sha-384
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_brainpoolP320r1_sha384_test.json (tcId:3)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA384,
			signatureAlg: oid.OidEcdsaWithSHA384,
			keyDer:       utils.HexToBytes("306a301406072a8648ce3d020106092b2403030208010109035200040fcc8860cb26e262ca8b4ecb9c52f78d82a10a1d30dd0c8ecd7584ce80dbb75c488a062b643755001f27e676c26cd3488c1ef4ec3edd88cf8af78daf9036724b57e66da02cf7c676a53664becdfedc3b"),
			signature:    utils.HexToBytes("305502290085b1bc586bf5407f9c8ec3765fe02bd19380998c45892ccd5081a1bd8872a26cdaf403e6dbf34a6e02285020e0be8664e256392c7a119f901c2acf390e5a7ab60f9d9b0b60f87348c05d7ea5a396785e5af5"),
		},
		{
			// brainpool384 / sha-384
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_brainpoolP384r1_sha384_test.json
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA384,
			signatureAlg: oid.OidEcdsaWithSHA384,
			keyDer:       utils.HexToBytes("307a301406072a8648ce3d020106092b240303020801010b03620004192ed5ce547d2336911d3f6cecba227f08df077f6242a9147a914e854e6e32d325fd23ccc42921dc4a7e4c2eb71defd3631e69079ba982e7a1cad0a39eff47fc6d6e3a280d081286b624886ba1f3069671ec1a29986d84fb79736d2799e6fc21"),
			signature:    utils.HexToBytes("306402300e8e114a1c351405560bf8d47b166bfe957087a8003b353433b6144f7ee7d6f79c8dd14ef229fa7a2f2782bf33708b910230090ea2de1d5c671a15cb3fe184889f4439b99cc37b82cb0618df9b8c0fa5f611e6a80f13cbac0f921c0ea6ed6dadeb41"),
		},
		{
			// brainpool512 / sha-512
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_brainpoolP512r1_sha512_test.json
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA512,
			signatureAlg: oid.OidEcdsaWithSHA512,
			keyDer:       utils.HexToBytes("30819b301406072a8648ce3d020106092b240303020801010d038182000467cea1bedf84cbdcba69a05bb2ce3a2d1c9d911d236c480929a16ad697b45a6ca127079fe8d7868671e28ef33bdf9319e2e51c84b190ac5c91b51baf0a980ba500a7e79006194b5378f65cbe625ef2c47c64e56040d873b995b5b1ebaa4a6ce971da164391ff619af3bcfc71c5e1ad27ee0e859c2943e2de8ef7c43d3c976e9b"),
			signature:    utils.HexToBytes("30818402400bd2593447cc6c02caf99d60418dd42e9a194c910e6755ed0c7059acac656b04ccfe1e8348462ee43066823aee2fed7ca012e9890dfb69866d7ae88b6506f9c7024066297ab3f5564b25270455d2689fd6b6076515606db7ebeefc91f709dca7ace18e51086e7a1f8c2e85ad79a052959077c58d4140cdf3cb60ec3b22e00cf194f8"),
		},
		{
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_secp192r1_sha256_test.json (tcId:3)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA256,
			signatureAlg: oid.OidEcdsaWithSHA256,
			keyDer:       utils.HexToBytes("3049301306072a8648ce3d020106082a8648ce3d03010103320004cd35a0b18eeb8fcd87ff019780012828745f046e785deba28150de1be6cb4376523006beff30ff09b4049125ced29723"),
			signature:    utils.HexToBytes("30350218184abdfc6df2ed2d0c9c7067af5552c0238ca4aa7f8f8a03021900af7bdc1fbd4ad6ba1de67516e5357afe03d5ac294865464d"),
		},
		{
			// secp224r1 / sha256
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_secp224r1_sha256_test.json (tcId:2)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA256,
			signatureAlg: oid.OidEcdsaWithSHA256,
			keyDer:       utils.HexToBytes("304e301006072a8648ce3d020106052b81040021033a0004eada93be10b2449e1e8bb58305d52008013c57107c1a20a317a6cba7eca672340c03d1d2e09663286691df55069fa25490c9dd9f9c0bb2b5"),
			signature:    utils.HexToBytes("303c021c3ade5c0624a5677ed7b6450d9420bbe028d499c23be9ef9d8b8a8a04021c617d6af141efd0c800c9ba3382c2faf758540a5dd98d1756a1dad981"),
		},
		{
			// secp256r1 / sha256
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_secp256r1_sha256_test.json (tcId:3)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA256,
			signatureAlg: oid.OidEcdsaWithSHA256,
			keyDer:       utils.HexToBytes("3059301306072a8648ce3d020106082a8648ce3d030107034200042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e"),
			signature:    utils.HexToBytes("304502202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db"),
		},
		{
			// secp256r1 / sha512
			//https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_secp256r1_sha512_test.json (tcId:3)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA512,
			signatureAlg: oid.OidEcdsaWithSHA512,
			keyDer:       utils.HexToBytes("3059301306072a8648ce3d020106082a8648ce3d030107034200042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e"),
			signature:    utils.HexToBytes("304502202478f1d049f6d857ac900a7af1772226a4c59b345fbb90613c66f42b98f981c0022100a07a59c4a41688538eb315e94effca0f4039035c6c2ed1dc84841359d1b34eb2"),
		},
		{
			// secp384r1 / sha512
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_secp384r1_sha512_test.json (tcId:4)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA512,
			signatureAlg: oid.OidEcdsaWithSHA512,
			keyDer:       utils.HexToBytes("3076301006072a8648ce3d020106052b81040022036200042da57dda1089276a543f9ffdac0bff0d976cad71eb7280e7d9bfd9fee4bdb2f20f47ff888274389772d98cc5752138aa4b6d054d69dcf3e25ec49df870715e34883b1836197d76f8ad962e78f6571bbc7407b0d6091f9e4d88f014274406174f"),
			signature:    utils.HexToBytes("3066023100814cc9a70febda342d4ada87fc39426f403d5e89808428460c1eca60c897bfd6728da14673854673d7d297ea944a15e202310084f5ef11d22f22d0548af6a50dbf2f6a1bb9054585af5e600c49cf35b1e69b712754dd781c837355ddd41c752193a7cd"),
		},
		{
			// secp521r1 / sha512
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_secp521r1_sha512_test.json (tcId:2)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA512,
			signatureAlg: oid.OidEcdsaWithSHA512,
			keyDer:       utils.HexToBytes("30819b301006072a8648ce3d020106052b810400230381860004005c6457ec088d532f482093965ae53ccd07e556ed59e2af945cd8c7a95c1c644f8a56a8a8a3cd77392ddd861e8a924dac99c69069093bd52a52fa6c56004a074508007878d6d42e4b4dd1e9c0696cb3e19f63033c3db4e60d473259b3ebe079aaf0a986ee6177f8217a78c68b813f7e149a4e56fd9562c07fed3d895942d7d101cb83f6"),
			signature:    utils.HexToBytes("30818602414e4223ee43e8cb89de3b1339ffc279e582f82c7ab0f71bbde43dbe374ac75ffbef29acdf8e70750b9a04f66fda48351de7bbfd515720b0ec5cd736f9b73bdf8645024128b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba2fe747122709a69ce69d5285e174a01a93022fea8318ac1"),
		},
	}
	for _, tc := range testCases {
		digest := cryptoutils.CryptoHashByOid(tc.digestAlg, tc.data)

		err := VerifySignature(tc.keyDer, tc.digestAlg, digest, tc.signatureAlg, tc.signature)

		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}
	}
}
