package document

import (
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestNewDG7NoData(t *testing.T) {
	if dg7, err := NewDG7(nil); dg7 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if dg7, err := NewDG7([]byte{}); dg7 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewDG7UnhappyRootTag(t *testing.T) {
	var dg7bytes []byte = utils.HexToBytes("01021234") // valid TLV but invalid DG7, as tag 67 is missing

	dg7, err := NewDG7(dg7bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg7 != nil {
		t.Errorf("DG7 not expected for error case")
	}
}

func TestNewDG7(t *testing.T) {
	data := utils.HexToBytes("678213f30201015f438213ebffd8ffe000104a46494600010201004800480000ffe100e84578696600004d4d002a000000080006011200030000000100010000011a00050000000100000056011b0005000000010000005e012800030000000100020000021300030000000100010000876900040000000100000066000000000000009000000001000000900000000100089000000700000004303232319101000700000004010203009286000700000012000000cca00000070000000430313030a00100030000000100010000a00200040000000100000094a00300040000000100000046a4060003000000010000000000000000415343494900000053637265656e73686f740000ffe20d144943435f50524f46494c4500010100000d046170706c021000006d6e74725247422058595a2007e800010001001100310009616373704150504c000000004150504c000000000000000000000000000000000000f6d6000100000000d32d6170706c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000116465736300000150000000626473636d000001b4000001e063707274000003940000002377747074000003b8000000147258595a000003cc000000146758595a000003e0000000146258595a000003f40000001472545243000004080000080c6161726700000c14000000207663677400000c34000000306e64696e00000c640000003e6d6d6f6400000ca4000000287663677000000ccc0000003862545243000004080000080c67545243000004080000080c6161626700000c14000000206161676700000c1400000020646573630000000000000008446973706c61790000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006d6c756300000000000000260000000c6872485200000008000001d86b6f4b5200000008000001d86e624e4f00000008000001d86964000000000008000001d86875485500000008000001d86373435a00000008000001d86461444b00000008000001d86e6c4e4c00000008000001d86669464900000008000001d86974495400000008000001d86573455300000008000001d8726f524f00000008000001d86672434100000008000001d86172000000000008000001d8756b554100000008000001d86865494c00000008000001d87a68545700000008000001d87669564e00000008000001d8736b534b00000008000001d87a68434e00000008000001d87275525500000008000001d8656e474200000008000001d86672465200000008000001d86d73000000000008000001d86869494e00000008000001d87468544800000008000001d86361455300000008000001d8656e415500000008000001d86573584c00000008000001d86465444500000008000001d8656e555300000008000001d87074425200000008000001d8706c504c00000008000001d8656c475200000008000001d87376534500000008000001d87472545200000008000001d87074505400000008000001d86a614a5000000008000001d80069004d006100637465787400000000436f70797269676874204170706c6520496e632e2c2032303234000058595a20000000000000f31600010000000116ca58595a2000000000000082ca00003cb7fffffffe58595a200000000000004c4a0000b4df00000aeb58595a2000000000000027c200000e6b0000c84463757276000000000000040000000005000a000f00140019001e00230028002d00320036003b00400045004a004f00540059005e00630068006d00720077007c00810086008b00900095009a009f00a300a800ad00b200b700bc00c100c600cb00d000d500db00e000e500eb00f000f600fb01010107010d01130119011f0125012b01320138013e0145014c0152015901600167016e0175017c0183018b0192019a01a101a901b101b901c101c901d101d901e101e901f201fa0203020c0214021d0226022f02380241024b0254025d02670271027a0284028e029802a202ac02b602c102cb02d502e002eb02f50300030b03160321032d03380343034f035a03660372037e038a039603a203ae03ba03c703d303e003ec03f9040604130420042d043b0448045504630471047e048c049a04a804b604c404d304e104f004fe050d051c052b053a05490558056705770586059605a605b505c505d505e505f6060606160627063706480659066a067b068c069d06af06c006d106e306f507070719072b073d074f076107740786079907ac07bf07d207e507f8080b081f08320846085a086e0882089608aa08be08d208e708fb09100925093a094f09640979098f09a409ba09cf09e509fb0a110a270a3d0a540a6a0a810a980aae0ac50adc0af30b0b0b220b390b510b690b800b980bb00bc80be10bf90c120c2a0c430c5c0c750c8e0ca70cc00cd90cf30d0d0d260d400d5a0d740d8e0da90dc30dde0df80e130e2e0e490e640e7f0e9b0eb60ed20eee0f090f250f410f5e0f7a0f960fb30fcf0fec1009102610431061107e109b10b910d710f511131131114f116d118c11aa11c911e81207122612451264128412a312c312e31303132313431363138313a413c513e5140614271449146a148b14ad14ce14f01512153415561578159b15bd15e0160316261649166c168f16b216d616fa171d17411765178917ae17d217f7181b18401865188a18af18d518fa19201945196b199119b719dd1a041a2a1a511a771a9e1ac51aec1b141b3b1b631b8a1bb21bda1c021c2a1c521c7b1ca31ccc1cf51d1e1d471d701d991dc31dec1e161e401e6a1e941ebe1ee91f131f3e1f691f941fbf1fea20152041206c209820c420f0211c2148217521a121ce21fb22272255228222af22dd230a23382366239423c223f0241f244d247c24ab24da250925382568259725c725f726272657268726b726e827182749277a27ab27dc280d283f287128a228d429062938296b299d29d02a022a352a682a9b2acf2b022b362b692b9d2bd12c052c392c6e2ca22cd72d0c2d412d762dab2de12e162e4c2e822eb72eee2f242f5a2f912fc72ffe3035306c30a430db3112314a318231ba31f2322a3263329b32d4330d3346337f33b833f1342b3465349e34d83513354d358735c235fd3637367236ae36e937243760379c37d738143850388c38c839053942397f39bc39f93a363a743ab23aef3b2d3b6b3baa3be83c273c653ca43ce33d223d613da13de03e203e603ea03ee03f213f613fa23fe24023406440a640e74129416a41ac41ee4230427242b542f7433a437d43c044034447448a44ce45124555459a45de4622466746ab46f04735477b47c04805484b489148d7491d496349a949f04a374a7d4ac44b0c4b534b9a4be24c2a4c724cba4d024d4a4d934ddc4e254e6e4eb74f004f494f934fdd5027507150bb51065150519b51e65231527c52c75313535f53aa53f65442548f54db5528557555c2560f565c56a956f75744579257e0582f587d58cb591a596959b85a075a565aa65af55b455b955be55c355c865cd65d275d785dc95e1a5e6c5ebd5f0f5f615fb36005605760aa60fc614f61a261f56249629c62f06343639763eb6440649464e9653d659265e7663d669266e8673d679367e9683f689668ec6943699a69f16a486a9f6af76b4f6ba76bff6c576caf6d086d606db96e126e6b6ec46f1e6f786fd1702b708670e0713a719571f0724b72a67301735d73b87414747074cc7528758575e1763e769b76f8775677b37811786e78cc792a798979e77a467aa57b047b637bc27c217c817ce17d417da17e017e627ec27f237f847fe5804780a8810a816b81cd8230829282f4835783ba841d848084e3854785ab860e867286d7873b879f8804886988ce8933899989fe8a648aca8b308b968bfc8c638cca8d318d988dff8e668ece8f368f9e9006906e90d6913f91a89211927a92e3934d93b69420948a94f4955f95c99634969f970a977597e0984c98b89924999099fc9a689ad59b429baf9c1c9c899cf79d649dd29e409eae9f1d9f8b9ffaa069a0d8a147a1b6a226a296a306a376a3e6a456a4c7a538a5a9a61aa68ba6fda76ea7e0a852a8c4a937a9a9aa1caa8fab02ab75abe9ac5cacd0ad44adb8ae2daea1af16af8bb000b075b0eab160b1d6b24bb2c2b338b3aeb425b49cb513b58ab601b679b6f0b768b7e0b859b8d1b94ab9c2ba3bbab5bb2ebba7bc21bc9bbd15bd8fbe0abe84beffbf7abff5c070c0ecc167c1e3c25fc2dbc358c3d4c451c4cec54bc5c8c646c6c3c741c7bfc83dc8bcc93ac9b9ca38cab7cb36cbb6cc35ccb5cd35cdb5ce36ceb6cf37cfb8d039d0bad13cd1bed23fd2c1d344d3c6d449d4cbd54ed5d1d655d6d8d75cd7e0d864d8e8d96cd9f1da76dafbdb80dc05dc8add10dd96de1cdea2df29dfafe036e0bde144e1cce253e2dbe363e3ebe473e4fce584e60de696e71fe7a9e832e8bce946e9d0ea5beae5eb70ebfbec86ed11ed9cee28eeb4ef40efccf058f0e5f172f1fff28cf319f3a7f434f4c2f550f5def66df6fbf78af819f8a8f938f9c7fa57fae7fb77fc07fc98fd29fdbafe4bfedcff6dffff706172610000000000030000000266660000f2a700000d59000013d000000a5b7663677400000000000000010001000000000000000100000001000000000000000100000001000000000000000100006e64696e00000000000000360000ae4000005140000043c00000b0c00000268000000d80000050000000544000023333000233330002333300000000000000006d6d6f6400000000000006100000ae1f50e5a070d478cfdd000000000000000000000000000000007663677000000000000300000002666600030000000266660003000000026666000000023333340000000002333334000000000233333400ffc00011080046009403012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffdb0043001c1c1c1c1c1c301c1c3044303030445c444444445c745c5c5c5c5c748c7474747474748c8c8c8c8c8c8c8ca8a8a8a8a8a8c4c4c4c4c4dcdcdcdcdcdcdcdcdcdcffdb00430122242438343860343460e69c809ce6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6ffdd0004000affda000c03010002110311003f00e928a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a00ffd0e928a28a0028a4240193c01598dac5886c6e247a8071401a9512cf0bb98d1d59875008c8c551b2bd9ef1cb795b61c1c313c920d7385a686f66ba879f2a439fa126803b6a89e786260b23aa93d0120669a97313db8b907e4c6ecd71f3c92dcdc25db8c2c8f85fa291fe3401dabba46a5e460aa3b9e0541f6db3ff009ec9ff007d0aabac7fc83e4ff80ff3155acb4cb29ad239248f2ccb92727fc6803691d241ba360c3d41cd41f6db3ff9ec9ff7d0ac258bec1ab2436ec76498c8fae7f975ab977a658c76d2c891e195490727ae3eb401a1f6db3ff9ec9ff7d0a95a7851048eea15ba12460d61699a7d9dc5a09664dcc49e7247f234fd6d163b28a3418556000f600d006b0bdb33c0993fefa1561595c6e52083dc565269360f12931f240e727fc6b3668a4d1a759a062d0b9c153fcbfc2803a8a2914860197907914b40051451401fffd1e928a28a00a3a9a48f632ac7c9c76f4cf354aceef4f4d3d51d946170ca7a93df8ef9ab7aab05b1932db32303dfdbf1ac4b78ee846ae2ca3718e091c9f7393fd28034743575b462dc2b312bf4c0a834d4592f2f11c65589047e26af58df8b976b778fca9107ddf6aafa6c52c77b72ee8ca198e09180793d280330db5e24a74b5cf94cdbb38edfe7f5ab5ab46909b48a31855240ff00c76ba4ac3d5e196596dcc68cc158e7009c74a00b3ac7fc83e4ff0080ff003159d6b06aed6c860991508e01eb8ffbe6b4f554792c5d2352cc71c0193d454d60ac96712b82085e41e0d0062e9a025fbc77809b8ecc4e7f2fc2b6efbfe3ce6ff71bf95666a30ca97d05dc28cd8e1b6827a1f6f635a978acf692aa824942001f4a00a5a2ff00c782ff00bc7f9d43af7fc7aa7fbe3f91ab3a44724564a92295393c118350eb714b2db22c4a5c87ce1467b1a00d587fd527fba3f95646bcca2d154f52e31f91a62ea37ca8116cdf2063273fe14c4b3bcbf9d67bf1b117a27f9fd68036ed815b6895ba845cfe553514500145145007ffd2e928a28a00a77f69f6db730e7690720fb8aa49fdb51a88f113638dc7fc8fe55b345006658d8c90caf7572c1a57e0e3a015a745140051451400514514005145140051451400514514005145140051451401ffd3e928a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a00ffd9")

	var doc Document

	err := doc.NewDG(7, data)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	expImageCnt := 1
	if len(doc.Mf.Lds1.Dg7.Images) != expImageCnt {
		t.Errorf("Incorrect image count (Exp:%1d, Act:%1d)", expImageCnt, len(doc.Mf.Lds1.Dg7.Images))
	}

	if len(doc.Mf.Lds1.Dg7.Images) > 0 {
		expImageLen := 5099
		if len(doc.Mf.Lds1.Dg7.Images[0].Image) != expImageLen {
			t.Errorf("Incorrect image length (Exp:%1d, Act:%1d)", expImageLen, len(doc.Mf.Lds1.Dg7.Images[0].Image))
		}
	}
}
