package gmrtd

import (
	"testing"
)

func TestNewSODNoData(t *testing.T) {
	if sod, err := NewSOD(nil); sod != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if sod, err := NewSOD([]byte{}); sod != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewSODUnhappyRootTag(t *testing.T) {
	var sodbytes []byte = HexToBytes("01021234") // valid TLV but invalid SOD, as tag 77 is missing

	sod, err := NewSOD(sodbytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if sod != nil {
		t.Errorf("SOD not expected for error case")
	}
}

func TestNewSOD(t *testing.T) {
	// AT
	data := HexToBytes("7782064d3082064906092a864886f70d010702a082063a30820636020103310f300d06096086480165030402010500308201120606678108010101a0820106048201023081ff020100300d060960864801650304020105003081ea3025020101042090462cd4824bc24ce1ce77e0e40da503b5f25063e61a78e22c3ac04e49b2024330250201020420113888bddfb89a94522959f3cf41007bb1241e2fdfa585d8f480317eb648215f302502010304205c1c4fa5fd3d90662a92d5c6c7ee94030ae7eed9070a6d8f1db376b268d99f83302502010b04202a1704fa33c5b3a5760eb8b48ff0ff9178e6470dc525b79b13bdcbc95d9d83d5302502010c0420c9673800c44a18a3d6e5300e6ad35ab8737dcdfb9f259e43bcff0c9b6a2d78a9302502010e0420aff8c92133072ed5703a84a5a6f5fe148f02a86b36b2d5876193bd48243cd2f2a08203e3308203df30820366a00302010202086189db18b6ede857300a06082a8648ce3d040303303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941301e170d3233303133313038303430325a170d3333303530363038303430325a3054310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d49310f300d060355040513063030343031353119301706035504030c1044532d415553545249412d654d525444308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200048893905193f315ee2e2f1eee3fd5a496f6637deb3778cfe7cc2f6c7f0682acc795b0290265a2cb83119343544f2bbfe42974159ac77b113dafbee860c2523c06a382015930820155301d0603551d0e04160414e76eaa567acf6568c660c985717c3c8a50bd024b301f0603551d230418301680142692c7e398abfbe35192d3f26e9a317d1fed53bd301a0603551d1004133011810f32303233303530363038303430325a30160603551d20040f300d300b06092a28000a0102010101303e0603551d1f043730353033a031a02f862d687474703a2f2f7777772e626d692e67762e61742f637363612f63726c2f43534341415553545249412e63726c300e0603551d0f0101ff04040302078030370603551d120430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f30370603551d110430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f301d06076781080101060204123010020100310b1301501302415213024944300a06082a8648ce3d040303036700306402303af7ae31ca6b8fafca6ec51985997f7119fb2e6d20d61b5327d5740109aa310b410bfb44f354e086f207fcab721e69ae023046c68fb7909f994350a2d1c84d1ae5dff8c00de6d86b7891a6cf90ceea09159402e6e2ed3fa548db28d33146319eefda318201213082011d020101304b303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d4155535452494102086189db18b6ede857300d06096086480165030402010500a066301506092a864886f70d01090331080606678108010101301c06092a864886f70d010905310f170d3233303331373133343031385a302f06092a864886f70d01090431220420eb5dd19b9688751461b3e61c9c80f1e848d91eec210048aca6653279c7c37c76300c06082a8648ce3d04030205000446304402202567959c119ee15d14520eab1b527c2bc493253d6733bbec30295af57e3ceb070220614dcea3ba92499e2212b9cd4159758cd49ae240e74b3e20d8d49183ed1feb09")

	// sod := NewSOD(data)
	sod, err := NewSOD(data)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if sod == nil {
		t.Errorf("SOD expected")
	}

	// TODO - test cases?
}

func TestNewSOD_MY(t *testing.T) {
	// MY
	data := HexToBytes("7782098e3082098a06092a864886f70d010702a082097b30820977020103310f300d06096086480165030402010500308201120606678108010101a0820106048201023081ff020100300d060960864801650304020105003081ea3025020101042070d01631abbf347f1fb7ca0b7e8fe6468b84fae853cb7fab2a2e05ef1519c58c30250201020420470beea11e946390967f3521407a29e258179661d6857e8a7d87a5afe9f23cb4302502010304204aea153d17588f1b22a886762789f911abd3ed9017e2d9a150967c70b6c61036302502010b0420a96b4199a460644233ab19cd648edee9c12c520365084356fb5cbb5f962c9024302502010c04206c00c5168e184d6b94129e79d4fbace2a0b4837b7ae196327cf7a8c567085872302502010e042056139d693f679511a91d67585aac748f0b70ca6e14417c1a73f15f205a03cc14a08205d0308205cc30820400a003020102020869ee7da36620dfab304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a2030201203081a0310b3009060355040613024d59310b300906035504080c0257503112301006035504070c0950757472616a61796131233021060355040a0c1a4a61626174616e20496d6967726573656e204d616c617973696131293027060355040b0c20426168616769616e204b6573656c616d6174616e2064616e20506173706f72743120301e06035504030c174d616c617973696120436f756e747279205369676e6572301e170d3232303831363039333731345a170d3238303831343039333731345a30819b311c301a06035504030c134d616c617973696120446f63205369676e657231293027060355040b0c20426168616769616e204b6573656c616d6174616e2064616e20506173706f727431233021060355040a0c1a4a61626174616e20496d6967726573656e204d616c6179736961310e300c06035504070c054a6f686f72310e300c06035504080c054a6f686f72310b3009060355040613024d5930820122300d06092a864886f70d01010105000382010f003082010a028201010098153deed15a97298a0190224b91725d0dbd872bc78da1e88b0a0acfc4d74904d2438be7ce7a0876cd4b50c0edfd3337c9278e76f1be9c3469c8ca45a786923eb73c044e2940a4dfe8dee5eb5d9ac46a2297d737a13ab6243418ad2ac2642a5858b79c6d494dcd835d9b8f32eae830c330c375530fb9024126fb050e03ba9c2addacfd7e3df1805c00a8d5aa55811f7f5ebe29cd2442c5e4cbc640468bfdd5b660ef5434e1cba0ad713886ba14acc9ffc3eff47d54b063bb97d2ac19eea1c00d5389b61dd8aeb249e010802d9f2923a56aedf54fd86011a07e89882e84b631588b94dafd3f0d638134ec2bf3335e53162ee1d066f4197f4ec1cc37d252c582db0203010001a38201233082011f301d0603551d0e04160414d63a217ed5886cec8406b8b3f161e0d3dc5379e7301f0603551d23041830168014d54dcf907ed448d2f40e059a3932b4660c9ec2db302e0603551d120427302581116a696d706b6940696d692e676f762e6d79a410300e310c300a06035504070c034d59533015060767810801010602040a30080201003103130150302b0603551d1004243022800f32303232303831363039333731345a810f32303233303832363039333731345a303b0603551d1f043430323030a02ea02c862a687474703a2f2f7777772e696d692e676f762e6d792f696d616765732f7064662f636163726c2e63726c300e0603551d0f0101ff040403020780301c0603551d110415301381116a696d706b6940696d692e676f762e6d79304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012003820181004a8caeeb0558a5c763262b003719e0d4cbc90ff6ed105af2793eac441f4a6cee1b78be1f4488e2439163ff5a708e50189a1a7d7fe6868ef7bb6c1dd1554cc322c94cc4f02ee9058c0a77a2a2aa5261a9f4fdfacf9fa68337aeeedfa33cbcf2a789887c1c7932cd59bb473d6a9c8f999819385d6517a2412696110514ab63a58672ddca1db5654a818b6714692008ec8da37793b759c222534f0d63cbacf6e9e8afe60ef70fe69ee9c83125710392c31dba5ed553b879a5b66fa2119ac4ef37dd43902b70dde59073b97ae5b5a111a7df3fcc3f471aa64927ed4adc8feb3d77036d16cb9a24e6692c0df7b4e4ae66b6b65a0f5caf036b4ecc432ef5326f29fa047a386390136a0f618e114a235a4db556dc9fc28f46553df18f315bcd611e8f790135ca5dbcc4cbc128bbe5b185925825558c67637c3f2f2586ae03b3f82238d9058b083d2aa1ebba422f7aa0344614a4f0c182383889097813f0c4b760b44272b1b387de5c4dda19d03a7f636f9e8843df927e04ac3667db6a3d456cadfd919b31820275308202710201013081ad3081a0310b3009060355040613024d5931233021060355040a0c1a4a61626174616e20496d6967726573656e204d616c6179736961310b300906035504080c0257503112301006035504070c0950757472616a61796131293027060355040b0c20426168616769616e204b6573656c616d6174616e2064616e20506173706f72743120301e06035504030c174d616c617973696120436f756e747279205369676e6572020869ee7da36620dfab300d06096086480165030402010500a066301506092a864886f70d01090331080606678108010101301c06092a864886f70d010905310f170d3233303132343036313931345a302f06092a864886f70d010904312204202ce83a982160f9753ea1a0d8d82f59c0ec9e40647d0015a702823143989a7eb6304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a2030201200482010096e3cb962a1d8cf79787783bcaa26cd80d2fed9282f97cd1f4a2a64f9170d459dc71e9d9a6f9a9eb259f0ef0bd064d3e17bc4c7bed1eeb4e8b73615f1335e1eab147f6bdd2d510afd3dc09b9dd36eb27db96a76045fa56acecbc1d4d5ce66df2a10d3ed3a9fb41d7c6d221a4568e74d496410c8c024006c7d6a990b2c5c8193b03f45c8a9fe11c17c9367ce7dc13c7813fe1abc9a79df39182bf76ddd6de44717ea6a5d3abcfb4c1c6e617543afa53d12719671590b4f48cd75e7ce79698237f3c589f7b224215fc11e97d19b0bd40c769898dc0701675dddd0bf129b5bfebda4b68d11a96cd073ace5590f63d1dddc2abd0970e6ea95a04792b1af82cc7195f")

	// sod := NewSOD(data)
	sod, err := NewSOD(data)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if sod == nil {
		t.Errorf("SOD expected")
	}

	// TODO - test cases?
}
