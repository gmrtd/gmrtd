package cms

import (
	"encoding/asn1"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

func TestVerifySignature(t *testing.T) {
	testCases := []struct {
		data         []byte
		digestAlg    asn1.ObjectIdentifier
		signatureAlg asn1.ObjectIdentifier
		keyDer       []byte
		signature    []byte
		expSuccess   bool
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
			expSuccess:   true,
		},
		{
			// brainpool256 / sha-256
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_brainpoolP256r1_sha256_test.json (tcId:2)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA256,
			signatureAlg: oid.OidEcdsaWithSHA256,
			keyDer:       utils.HexToBytes("305a301406072a8648ce3d020106092b240303020801010703420004019a2d9637743a63ddaefdbca0ee229a163b809b9b145e5313bbeb8defeab9d6548caf89bf5ba49499404145651234336401b9b2843a579ed152e090f11b9e59"),
			signature:    utils.HexToBytes("304402200a5f8c70ba2d0842d5d0f841f160ad15195769a8159bfe692634d73d469d111f0220678cd260f4aeb211a781388fdd48478007cf43d32b736de019916ce1c0737c39"),
			expSuccess:   true,
		},
		{
			// brainpool320 / sha-384
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_brainpoolP320r1_sha384_test.json (tcId:3)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA384,
			signatureAlg: oid.OidEcdsaWithSHA384,
			keyDer:       utils.HexToBytes("306a301406072a8648ce3d020106092b2403030208010109035200040fcc8860cb26e262ca8b4ecb9c52f78d82a10a1d30dd0c8ecd7584ce80dbb75c488a062b643755001f27e676c26cd3488c1ef4ec3edd88cf8af78daf9036724b57e66da02cf7c676a53664becdfedc3b"),
			signature:    utils.HexToBytes("305502290085b1bc586bf5407f9c8ec3765fe02bd19380998c45892ccd5081a1bd8872a26cdaf403e6dbf34a6e02285020e0be8664e256392c7a119f901c2acf390e5a7ab60f9d9b0b60f87348c05d7ea5a396785e5af5"),
			expSuccess:   true,
		},
		{
			// brainpool384 / sha-384
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_brainpoolP384r1_sha384_test.json
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA384,
			signatureAlg: oid.OidEcdsaWithSHA384,
			keyDer:       utils.HexToBytes("307a301406072a8648ce3d020106092b240303020801010b03620004192ed5ce547d2336911d3f6cecba227f08df077f6242a9147a914e854e6e32d325fd23ccc42921dc4a7e4c2eb71defd3631e69079ba982e7a1cad0a39eff47fc6d6e3a280d081286b624886ba1f3069671ec1a29986d84fb79736d2799e6fc21"),
			signature:    utils.HexToBytes("306402300e8e114a1c351405560bf8d47b166bfe957087a8003b353433b6144f7ee7d6f79c8dd14ef229fa7a2f2782bf33708b910230090ea2de1d5c671a15cb3fe184889f4439b99cc37b82cb0618df9b8c0fa5f611e6a80f13cbac0f921c0ea6ed6dadeb41"),
			expSuccess:   true,
		},
		{
			// brainpool512 / sha-512
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_brainpoolP512r1_sha512_test.json
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA512,
			signatureAlg: oid.OidEcdsaWithSHA512,
			keyDer:       utils.HexToBytes("30819b301406072a8648ce3d020106092b240303020801010d038182000467cea1bedf84cbdcba69a05bb2ce3a2d1c9d911d236c480929a16ad697b45a6ca127079fe8d7868671e28ef33bdf9319e2e51c84b190ac5c91b51baf0a980ba500a7e79006194b5378f65cbe625ef2c47c64e56040d873b995b5b1ebaa4a6ce971da164391ff619af3bcfc71c5e1ad27ee0e859c2943e2de8ef7c43d3c976e9b"),
			signature:    utils.HexToBytes("30818402400bd2593447cc6c02caf99d60418dd42e9a194c910e6755ed0c7059acac656b04ccfe1e8348462ee43066823aee2fed7ca012e9890dfb69866d7ae88b6506f9c7024066297ab3f5564b25270455d2689fd6b6076515606db7ebeefc91f709dca7ace18e51086e7a1f8c2e85ad79a052959077c58d4140cdf3cb60ec3b22e00cf194f8"),
			expSuccess:   true,
		},
		{
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_secp192r1_sha256_test.json (tcId:3)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA256,
			signatureAlg: oid.OidEcdsaWithSHA256,
			keyDer:       utils.HexToBytes("3049301306072a8648ce3d020106082a8648ce3d03010103320004cd35a0b18eeb8fcd87ff019780012828745f046e785deba28150de1be6cb4376523006beff30ff09b4049125ced29723"),
			signature:    utils.HexToBytes("30350218184abdfc6df2ed2d0c9c7067af5552c0238ca4aa7f8f8a03021900af7bdc1fbd4ad6ba1de67516e5357afe03d5ac294865464d"),
			expSuccess:   true,
		},
		{
			// secp224r1 / sha256
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_secp224r1_sha256_test.json (tcId:2)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA256,
			signatureAlg: oid.OidEcdsaWithSHA256,
			keyDer:       utils.HexToBytes("304e301006072a8648ce3d020106052b81040021033a0004eada93be10b2449e1e8bb58305d52008013c57107c1a20a317a6cba7eca672340c03d1d2e09663286691df55069fa25490c9dd9f9c0bb2b5"),
			signature:    utils.HexToBytes("303c021c3ade5c0624a5677ed7b6450d9420bbe028d499c23be9ef9d8b8a8a04021c617d6af141efd0c800c9ba3382c2faf758540a5dd98d1756a1dad981"),
			expSuccess:   true,
		},
		{
			// secp256r1 / sha256
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_secp256r1_sha256_test.json (tcId:3)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA256,
			signatureAlg: oid.OidEcdsaWithSHA256,
			keyDer:       utils.HexToBytes("3059301306072a8648ce3d020106082a8648ce3d030107034200042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e"),
			signature:    utils.HexToBytes("304502202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db"),
			expSuccess:   true,
		},
		{
			// secp256r1 / sha512
			//https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_secp256r1_sha512_test.json (tcId:3)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA512,
			signatureAlg: oid.OidEcdsaWithSHA512,
			keyDer:       utils.HexToBytes("3059301306072a8648ce3d020106082a8648ce3d030107034200042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e"),
			signature:    utils.HexToBytes("304502202478f1d049f6d857ac900a7af1772226a4c59b345fbb90613c66f42b98f981c0022100a07a59c4a41688538eb315e94effca0f4039035c6c2ed1dc84841359d1b34eb2"),
			expSuccess:   true,
		},
		{
			// secp384r1 / sha512
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_secp384r1_sha512_test.json (tcId:4)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA512,
			signatureAlg: oid.OidEcdsaWithSHA512,
			keyDer:       utils.HexToBytes("3076301006072a8648ce3d020106052b81040022036200042da57dda1089276a543f9ffdac0bff0d976cad71eb7280e7d9bfd9fee4bdb2f20f47ff888274389772d98cc5752138aa4b6d054d69dcf3e25ec49df870715e34883b1836197d76f8ad962e78f6571bbc7407b0d6091f9e4d88f014274406174f"),
			signature:    utils.HexToBytes("3066023100814cc9a70febda342d4ada87fc39426f403d5e89808428460c1eca60c897bfd6728da14673854673d7d297ea944a15e202310084f5ef11d22f22d0548af6a50dbf2f6a1bb9054585af5e600c49cf35b1e69b712754dd781c837355ddd41c752193a7cd"),
			expSuccess:   true,
		},
		{
			// secp521r1 / sha512
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/ecdsa_secp521r1_sha512_test.json (tcId:2)
			data:         utils.HexToBytes("313233343030"),
			digestAlg:    oid.OidHashAlgorithmSHA512,
			signatureAlg: oid.OidEcdsaWithSHA512,
			keyDer:       utils.HexToBytes("30819b301006072a8648ce3d020106052b810400230381860004005c6457ec088d532f482093965ae53ccd07e556ed59e2af945cd8c7a95c1c644f8a56a8a8a3cd77392ddd861e8a924dac99c69069093bd52a52fa6c56004a074508007878d6d42e4b4dd1e9c0696cb3e19f63033c3db4e60d473259b3ebe079aaf0a986ee6177f8217a78c68b813f7e149a4e56fd9562c07fed3d895942d7d101cb83f6"),
			signature:    utils.HexToBytes("30818602414e4223ee43e8cb89de3b1339ffc279e582f82c7ab0f71bbde43dbe374ac75ffbef29acdf8e70750b9a04f66fda48351de7bbfd515720b0ec5cd736f9b73bdf8645024128b5d0926a4172b349b0fd2e929487a5edb94b142df923a697e7446acdacdba0a029e43d69111174dba2fe747122709a69ce69d5285e174a01a93022fea8318ac1"),
			expSuccess:   true,
		},
		{
			// rsa_signature_2048_sha512
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/rsa_signature_2048_sha512_test.json (tcId:3)
			data:         utils.HexToBytes("54657374"),
			digestAlg:    oid.OidHashAlgorithmSHA512,
			signatureAlg: oid.OidSha512WithRSAEncryption,
			keyDer:       utils.HexToBytes("30820122300d06092a864886f70d01010105000382010f003082010a0282010100c2c4a860236d3c9096a076d6ba5107e0f7bd81e1ba916f7375724bd2b0b0b63956813715a3457ab0458b71fb35a45b27f9ef7ac3e579dea45dfbfd07819ed6b7021aa5336c58442aadd96ca9ee9d32473e9d9278562b4d10258ade6a98fb1c7cfdc3b3716ef5dec58cf73b359f389599b4b5865a9863519eb001c324387da755450db341309360e3807c0565b8e2c44fbd5e6e8d04d006d7ee768b8e8436082a90fa0e837f32f46087ab4a0d9be28aa7da1794ceb0172a7f50ed20f6df641efbcbfd2aac89775c761a7310093c671c977fa18b0d6e01fb25f7a432b42c65359784c689205719c1cf6e3a65dae2da434c326dde81bb6ffffbdbf6de5c16bba7490203010001"),
			signature:    utils.HexToBytes("a0f46582cde6be215351bb7b29e8ff24398816fad9e7e2ed6ccf1d0b5296bad827316c18b1565253291fa1c0baea9a735357cff8920e1024ae5707dd2f0cfcc9e6cc81402217d9b4f51e10def2bc2f4924e7d22c022fc87d6c3e772f4952050d027b003ab4267ff227a15cc7c884cdb46bbc7eb38852d0e6d8a12f485ccb0312157097687debb6feaf2b6dac998224c6047c1d5727195bb8ce05a59669034e88de0e4815af00c65def5b9748d017455056cc1ac6d3a77e31fcea4e726eda6be7bd33e509696e54d1d1858a1165fa9ece5d62e493c1a33ab3c94d294838a19f367fb799d6b69161bd9532a6ef317deb919923d78e33309f14a97b68023d600b4d"),
			expSuccess:   true,
		},
		{
			// rsa_signature_2048_sha512
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/rsa_signature_2048_sha512_test.json (tcId:3)
			data:         utils.HexToBytes("54657373"), // NB last byte changed from x74 to x73
			digestAlg:    oid.OidHashAlgorithmSHA512,
			signatureAlg: oid.OidSha512WithRSAEncryption,
			keyDer:       utils.HexToBytes("30820122300d06092a864886f70d01010105000382010f003082010a0282010100c2c4a860236d3c9096a076d6ba5107e0f7bd81e1ba916f7375724bd2b0b0b63956813715a3457ab0458b71fb35a45b27f9ef7ac3e579dea45dfbfd07819ed6b7021aa5336c58442aadd96ca9ee9d32473e9d9278562b4d10258ade6a98fb1c7cfdc3b3716ef5dec58cf73b359f389599b4b5865a9863519eb001c324387da755450db341309360e3807c0565b8e2c44fbd5e6e8d04d006d7ee768b8e8436082a90fa0e837f32f46087ab4a0d9be28aa7da1794ceb0172a7f50ed20f6df641efbcbfd2aac89775c761a7310093c671c977fa18b0d6e01fb25f7a432b42c65359784c689205719c1cf6e3a65dae2da434c326dde81bb6ffffbdbf6de5c16bba7490203010001"),
			signature:    utils.HexToBytes("a0f46582cde6be215351bb7b29e8ff24398816fad9e7e2ed6ccf1d0b5296bad827316c18b1565253291fa1c0baea9a735357cff8920e1024ae5707dd2f0cfcc9e6cc81402217d9b4f51e10def2bc2f4924e7d22c022fc87d6c3e772f4952050d027b003ab4267ff227a15cc7c884cdb46bbc7eb38852d0e6d8a12f485ccb0312157097687debb6feaf2b6dac998224c6047c1d5727195bb8ce05a59669034e88de0e4815af00c65def5b9748d017455056cc1ac6d3a77e31fcea4e726eda6be7bd33e509696e54d1d1858a1165fa9ece5d62e493c1a33ab3c94d294838a19f367fb799d6b69161bd9532a6ef317deb919923d78e33309f14a97b68023d600b4d"),
			expSuccess:   false,
		},
		{
			// rsa_pss_4096_sha512
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/rsa_pss_4096_sha512_mgf1_32_test.json (tcId:3)
			data:         utils.HexToBytes("54657374"),
			digestAlg:    oid.OidHashAlgorithmSHA512,
			signatureAlg: oid.OidRsaSsaPss,
			keyDer:       utils.HexToBytes("30820222300d06092a864886f70d01010105000382020f003082020a0282020100c9a765c2661b4674cff3480e9a5e462ad0ad2fc9bc6fbef62847b3113d20991f653967971c28252753f5fbacce012c2a8ab592914d269efafa724fa4b920e340930c106f7b36f79cebf0e62e88e0e476888e9f0e22186acdb6c4523a232b65b4ff2cc22dc44f8a559527d79d7cd7dcf3773212f7bb9aa133c31165cc663690bf123d73923c838929ccafee59d6c7095b8d4a74baf2d192c9a4e87c4e12bc58013078b28a7789e82e9f31de1f4d6a2aa6e80632be8e4bdf263e8d49b09416fb19c488c07ad8af722ab79182b23028a71e065d02412a9eebc46d7d8f4e03d79238d8c0cb4a97a9a1200ebb6ec64042ebeccad9567526eeef12c17d94c1049c889970b96e94cc353172a268a49c5e8bee13c15b39dec44f2c7a1aa37a7a0b6f72290acada32b1d8af1fc3dc8a89487ba81347cbeb1350925d30f923958106b49959c871e7c1dba55da0772e362cf8621d78610868b894e16e5dfec96874a93a4cf379b47e7e318ce315066d70ee3938140a60148f205085cef8a7700ca3c53d52a5756a63b3b16f153062b61262a68496210c8be4ef3f9029ca0ea0e3b3a0d5d6d226edbbf44daf8f045dc286ded3c4ec4db6b45347079f33eaf98e3c95b4b60e79ef4a3093feec543703422ba74a118511c2193b54fe8b633866ed2c705ccbc6e7d9d3656809ec3d3356e7400a9648ec37505041e3e31af1c02eefe924a67047d30203010001"),
			signature:    utils.HexToBytes("7c838ba65f923660aa4ac47465eb1df4df51d6fa2be26389757de8c6dfc7746aa5164d909b69b7c04758d256e13e3520e77e75b4094d8b0d60da0030b9c991969f6e892ff03ffba9b9f95ca991a279e7cded611a2879e6e6602f411a122c8d11cd333de5d2f7f367e38ee0491380e8796e113487ec7bc05ec1b1261aff871ef82cdd12f4e3d8f239cd49b2f53d57255dfe6ef29038831cdebe9cb1a76dc9ed79578e129b063724ccb3c7b3269f5dd3d9669a405582255cb56b1efe6d61a376df3a141014c3d660b66f9d1b266b5fd3c5472534df778e6e022a8f5a6cab501dde611e07c0c8eb5718962692e8e3773bfd25f1d3b63a20a251ef0c296f01f4a17814e18dfc029f2ed0ce073e83777cff44471f9348434fcc12b0420bf2de1c9018f0282ee21f09302b178f8c772c8f8962f6a29291c63532e1ae9301e7ac55781876965f425619a92559f33737d5e11b282f9434e27d9b27eb2fb0fce4e3e90ca9eaafef170644b00e512537bd779fd2207ee73020aaec07e6cd44103a14940c9499b013c42440d2f27a3def34f3509cd8631db1cc8633ac15180272c824369e1d3c8a6cdca511748361cb60e022173f95ad06e7c79d59e03934854a9f9827f3593d87c34d3fc44beec58e107d454ce04b55c96effce612aef0e5d55c31e367c9fc0166f2c9d450e86d79323d4da8fb409f97adc7af2ec6772ab290f622fe1fa61"),
			expSuccess:   true,
		},
		{
			// rsa_pss_4096_sha512
			// https://github.com/C2SP/wycheproof/blob/master/testvectors/rsa_pss_4096_sha512_mgf1_32_test.json (tcId:3)
			data:         utils.HexToBytes("54657364"), // NB last byte changed from x74 to x64
			digestAlg:    oid.OidHashAlgorithmSHA512,
			signatureAlg: oid.OidRsaSsaPss,
			keyDer:       utils.HexToBytes("30820222300d06092a864886f70d01010105000382020f003082020a0282020100c9a765c2661b4674cff3480e9a5e462ad0ad2fc9bc6fbef62847b3113d20991f653967971c28252753f5fbacce012c2a8ab592914d269efafa724fa4b920e340930c106f7b36f79cebf0e62e88e0e476888e9f0e22186acdb6c4523a232b65b4ff2cc22dc44f8a559527d79d7cd7dcf3773212f7bb9aa133c31165cc663690bf123d73923c838929ccafee59d6c7095b8d4a74baf2d192c9a4e87c4e12bc58013078b28a7789e82e9f31de1f4d6a2aa6e80632be8e4bdf263e8d49b09416fb19c488c07ad8af722ab79182b23028a71e065d02412a9eebc46d7d8f4e03d79238d8c0cb4a97a9a1200ebb6ec64042ebeccad9567526eeef12c17d94c1049c889970b96e94cc353172a268a49c5e8bee13c15b39dec44f2c7a1aa37a7a0b6f72290acada32b1d8af1fc3dc8a89487ba81347cbeb1350925d30f923958106b49959c871e7c1dba55da0772e362cf8621d78610868b894e16e5dfec96874a93a4cf379b47e7e318ce315066d70ee3938140a60148f205085cef8a7700ca3c53d52a5756a63b3b16f153062b61262a68496210c8be4ef3f9029ca0ea0e3b3a0d5d6d226edbbf44daf8f045dc286ded3c4ec4db6b45347079f33eaf98e3c95b4b60e79ef4a3093feec543703422ba74a118511c2193b54fe8b633866ed2c705ccbc6e7d9d3656809ec3d3356e7400a9648ec37505041e3e31af1c02eefe924a67047d30203010001"),
			signature:    utils.HexToBytes("7c838ba65f923660aa4ac47465eb1df4df51d6fa2be26389757de8c6dfc7746aa5164d909b69b7c04758d256e13e3520e77e75b4094d8b0d60da0030b9c991969f6e892ff03ffba9b9f95ca991a279e7cded611a2879e6e6602f411a122c8d11cd333de5d2f7f367e38ee0491380e8796e113487ec7bc05ec1b1261aff871ef82cdd12f4e3d8f239cd49b2f53d57255dfe6ef29038831cdebe9cb1a76dc9ed79578e129b063724ccb3c7b3269f5dd3d9669a405582255cb56b1efe6d61a376df3a141014c3d660b66f9d1b266b5fd3c5472534df778e6e022a8f5a6cab501dde611e07c0c8eb5718962692e8e3773bfd25f1d3b63a20a251ef0c296f01f4a17814e18dfc029f2ed0ce073e83777cff44471f9348434fcc12b0420bf2de1c9018f0282ee21f09302b178f8c772c8f8962f6a29291c63532e1ae9301e7ac55781876965f425619a92559f33737d5e11b282f9434e27d9b27eb2fb0fce4e3e90ca9eaafef170644b00e512537bd779fd2207ee73020aaec07e6cd44103a14940c9499b013c42440d2f27a3def34f3509cd8631db1cc8633ac15180272c824369e1d3c8a6cdca511748361cb60e022173f95ad06e7c79d59e03934854a9f9827f3593d87c34d3fc44beec58e107d454ce04b55c96effce612aef0e5d55c31e367c9fc0166f2c9d450e86d79323d4da8fb409f97adc7af2ec6772ab290f622fe1fa61"),
			expSuccess:   false,
		},
	}
	for i, tc := range testCases {
		digest, err := cryptoutils.CryptoHashByOid(tc.digestAlg, tc.data)
		if err != nil {
			t.Errorf("Test case %d: CryptoHashByOid error: %s", i, err)
		}

		err = VerifySignature(tc.keyDer, tc.digestAlg, digest, tc.signatureAlg, tc.signature)

		if tc.expSuccess {
			if err != nil {
				t.Errorf("Test case %d: Unexpected error: %s", i, err)
			}
		} else {
			if err == nil {
				t.Errorf("Test case %d: Error expected", i)
			}
		}
	}
}
