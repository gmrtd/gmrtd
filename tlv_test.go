package gmrtd

import (
	"bytes"
	"reflect"
	"testing"
)

func TestTlv(t *testing.T) {
	data := HexToBytes("31283012060a04007f000702020402040201020201103012060a04007f00070202040604020102020110")

	nodes := TlvDecode(data)

	data2 := nodes.Encode()

	if !bytes.Equal(data, data2) {
		t.Errorf("Decode/Encode mismatch (Exp: %x) (Act: %x)", data, data2)
	}
}

func TestTlvIsConstructedTag(t *testing.T) {
	testCases := []struct {
		tag           TlvTag
		isConstructed bool
	}{
		{
			tag:           0x61,
			isConstructed: true,
		},
		{
			tag:           0x7f61,
			isConstructed: true,
		},
		{
			tag:           0x5f1f,
			isConstructed: false,
		},
		{
			tag:           0x81,
			isConstructed: false,
		},
	}
	for _, tc := range testCases {
		actIsConstructed := TlvIsConstructedTag(tc.tag)
		if actIsConstructed != tc.isConstructed {
			t.Errorf("TlvIsConstructedTag error (Tag:%x, Exp:%t, Act:%t)", tc.tag, tc.isConstructed, actIsConstructed)
		}
	}

}

func TestTlvDecode(t *testing.T) {

	inp := HexToBytes("61085f1f050123456789")
	out := TlvDecode(inp)

	act := out.GetNode(0x61).GetNode(0x5f1f).GetValue()

	exp := HexToBytes("0123456789")

	if !bytes.Equal(exp, act) {
		t.Errorf("TLV Decode error (Exp:%x, Act:%x)", exp, act)
	}
}

func TestTlvGetTags(t *testing.T) {
	testCases := []struct {
		inp    []byte
		expOut []TlvTag
	}{
		{
			inp:    HexToBytes("5F0E5F115F425F125F13"),
			expOut: []TlvTag{0x5F0E, 0x5F11, 0x5F42, 0x5F12, 0x5F13},
		},
		{
			inp:    HexToBytes("A0305F1F80887F6002"),
			expOut: []TlvTag{0xA0, 0x30, 0x5F1F, 0x80, 0x88, 0x7F60, 0x02},
		},
	}
	for _, tc := range testCases {
		actOut := TlvGetTags(bytes.NewBuffer(tc.inp))

		if !reflect.DeepEqual(actOut, tc.expOut) {
			t.Errorf("TLV Tags differs to expected (Exp:%x, Act:%x)", tc.expOut, actOut)
		}
	}

}

func TestTlvLength(t *testing.T) {
	testCases := []struct {
		inp    int
		expOut []byte
	}{
		{
			// special case for indefinite-length mode
			inp:    -1,
			expOut: HexToBytes("80"),
		},
		{
			inp:    0x7F,
			expOut: HexToBytes("7F"),
		},
		{
			inp:    0x80,
			expOut: HexToBytes("8180"),
		},
		{
			inp:    0xFF,
			expOut: HexToBytes("81FF"),
		},
		{
			inp:    0xFFFF,
			expOut: HexToBytes("82FFFF"),
		},
		{
			inp:    0xFFFFFF,
			expOut: HexToBytes("83FFFFFF"),
		},
		{
			inp:    0xFFFFFFFF,
			expOut: HexToBytes("84FFFFFFFF"),
		},
	}
	for _, tc := range testCases {
		actOut := TlvEncodeLength(int(tc.inp))

		if !bytes.Equal(actOut, tc.expOut) {
			t.Errorf("Invalid TLV Length encoding (Len:%x, ExpBytes:%x, ActBytes:%x)", tc.inp, tc.expOut, actOut)
		}

		// test decode
		{
			var bBuf *bytes.Buffer = bytes.NewBuffer(actOut)
			decodedLen := TlvGetLength(bBuf)

			if decodedLen != int(tc.inp) {
				t.Errorf("TLV Length decode error (EncLen:%x, ExpLen:%x, ActLen:%x)", actOut, tc.inp, decodedLen)
			}

			if len(bBuf.Bytes()) > 0 {
				t.Errorf("Unexpected data left in buffer")
			}
		}
	}
}

func TestTlvParseAndAccess(t *testing.T) {
	//	70
	//		02: 0x123456
	//		A0
	//			01: 0x7890
	//			02: 0x45
	//			01: 0x67

	var tlvBytes []byte = HexToBytes("70110203123456A00A01027890020145010167")

	var nodes *TlvNodes = TlvDecode(tlvBytes)

	/*
	* basic tests for value access
	 */
	if !bytes.Equal(nodes.GetNode(0x70).GetNode(0x02).GetValue(), HexToBytes("123456")) ||
		!bytes.Equal(nodes.GetNode(0x70).GetNode(0xA0).GetNodeByOccur(0x01, 1).GetValue(), HexToBytes("7890")) ||
		!bytes.Equal(nodes.GetNode(0x70).GetNode(0xA0).GetNodeByOccur(0x02, 1).GetValue(), HexToBytes("45")) ||
		!bytes.Equal(nodes.GetNode(0x70).GetNode(0xA0).GetNodeByOccur(0x01, 2).GetValue(), HexToBytes("67")) {
		t.Errorf("Error fetching value from TLV")
	}

	/*
	* IsValidNode - positive cases
	 */
	if !nodes.IsValidNode() ||
		!nodes.GetNode(0x70).IsValidNode() ||
		!nodes.GetNode(0x70).GetNode(0x02).IsValidNode() ||
		!nodes.GetNode(0x70).GetNode(0xA0).IsValidNode() {
		t.Errorf("IsValidNode error for positive cases")
	}

	/*
	* test that trying to access absent tags does not cause problems
	 */

	if nodes.GetNode(0x71).IsValidNode() ||
		nodes.GetNode(0x70).GetNode(0x02).GetNode(0x01).IsValidNode() ||
		nodes.GetNode(0x70).GetNode(0x02).GetNodeByOccur(0x01, 3).IsValidNode() ||
		nodes.GetNode(0x70).GetNode(0x02).GetNode(0x01).GetNode(0x01).IsValidNode() ||
		nodes.GetNode(0x70).GetNode(0x02).GetNode(0x01).GetNodeByOccur(0x01, 1).IsValidNode() ||
		(nodes.GetNode(0x70).GetNode(0x02).GetNode(0x01).GetNode(0x01).GetTag() != -1) ||
		nodes.GetNodeByOccur(0x70, 2).IsValidNode() ||
		nodes.GetNode(0x70).GetNode(0xA0).GetNodeByOccur(0x02, 2).IsValidNode() {
		t.Errorf("Absent tags not handled correctly")
	}
}

func TestTlvParseAndAccessIndefiniteLength(t *testing.T) {
	// NB modified test case for tags using indefinite-length mode

	//	70
	//		02: 0x123456
	//		A0					** indefinite-length
	//			01: 0x7890
	//			02: 0x45
	//			01: 0x67
	//		A0
	//			01: 0x1234

	var tlvBytes []byte = HexToBytes("70190203123456A080010278900201450101670000A00401021234")

	var nodes *TlvNodes = TlvDecode(tlvBytes)

	/*
	* basic tests for value access
	 */
	if !bytes.Equal(nodes.GetNode(0x70).GetNode(0x02).GetValue(), HexToBytes("123456")) ||
		!bytes.Equal(nodes.GetNode(0x70).GetNode(0xA0).GetNodeByOccur(0x01, 1).GetValue(), HexToBytes("7890")) ||
		!bytes.Equal(nodes.GetNode(0x70).GetNode(0xA0).GetNodeByOccur(0x02, 1).GetValue(), HexToBytes("45")) ||
		!bytes.Equal(nodes.GetNode(0x70).GetNode(0xA0).GetNodeByOccur(0x01, 2).GetValue(), HexToBytes("67")) ||
		!bytes.Equal(nodes.GetNode(0x70).GetNodeByOccur(0xA0, 2).GetNode(0x01).GetValue(), HexToBytes("1234")) {
		t.Errorf("Error fetching value from TLV")
	}

	/*
	* IsValidNode - positive cases
	 */
	if !nodes.IsValidNode() ||
		!nodes.GetNode(0x70).IsValidNode() ||
		!nodes.GetNode(0x70).GetNode(0x02).IsValidNode() ||
		!nodes.GetNode(0x70).GetNode(0xA0).IsValidNode() {
		t.Errorf("IsValidNode error for positive cases")
	}

	/*
	* test that trying to access absent tags does not cause problems
	 */

	if nodes.GetNode(0x71).IsValidNode() ||
		nodes.GetNode(0x70).GetNode(0x02).GetNode(0x01).IsValidNode() ||
		nodes.GetNode(0x70).GetNode(0x02).GetNodeByOccur(0x01, 3).IsValidNode() ||
		nodes.GetNode(0x70).GetNode(0x02).GetNode(0x01).GetNode(0x01).IsValidNode() ||
		nodes.GetNode(0x70).GetNode(0x02).GetNode(0x01).GetNodeByOccur(0x01, 1).IsValidNode() ||
		(nodes.GetNode(0x70).GetNode(0x02).GetNode(0x01).GetNode(0x01).GetTag() != -1) ||
		nodes.GetNodeByOccur(0x70, 2).IsValidNode() ||
		nodes.GetNode(0x70).GetNode(0xA0).GetNodeByOccur(0x02, 2).IsValidNode() {
		t.Errorf("Absent tags not handled correctly")
	}
}

func TestTlvToString(t *testing.T) {
	// this is somewhat of a cosmetic test, but it serves to executre the code and ensure no major exceptions

	// SOD (AT) sample
	sodBytes := HexToBytes("7782064d3082064906092a864886f70d010702a082063a30820636020103310f300d06096086480165030402010500308201120606678108010101a0820106048201023081ff020100300d060960864801650304020105003081ea3025020101042090462cd4824bc24ce1ce77e0e40da503b5f25063e61a78e22c3ac04e49b2024330250201020420113888bddfb89a94522959f3cf41007bb1241e2fdfa585d8f480317eb648215f302502010304205c1c4fa5fd3d90662a92d5c6c7ee94030ae7eed9070a6d8f1db376b268d99f83302502010b04202a1704fa33c5b3a5760eb8b48ff0ff9178e6470dc525b79b13bdcbc95d9d83d5302502010c0420c9673800c44a18a3d6e5300e6ad35ab8737dcdfb9f259e43bcff0c9b6a2d78a9302502010e0420aff8c92133072ed5703a84a5a6f5fe148f02a86b36b2d5876193bd48243cd2f2a08203e3308203df30820366a00302010202086189db18b6ede857300a06082a8648ce3d040303303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941301e170d3233303133313038303430325a170d3333303530363038303430325a3054310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d49310f300d060355040513063030343031353119301706035504030c1044532d415553545249412d654d525444308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200048893905193f315ee2e2f1eee3fd5a496f6637deb3778cfe7cc2f6c7f0682acc795b0290265a2cb83119343544f2bbfe42974159ac77b113dafbee860c2523c06a382015930820155301d0603551d0e04160414e76eaa567acf6568c660c985717c3c8a50bd024b301f0603551d230418301680142692c7e398abfbe35192d3f26e9a317d1fed53bd301a0603551d1004133011810f32303233303530363038303430325a30160603551d20040f300d300b06092a28000a0102010101303e0603551d1f043730353033a031a02f862d687474703a2f2f7777772e626d692e67762e61742f637363612f63726c2f43534341415553545249412e63726c300e0603551d0f0101ff04040302078030370603551d120430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f30370603551d110430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f301d06076781080101060204123010020100310b1301501302415213024944300a06082a8648ce3d040303036700306402303af7ae31ca6b8fafca6ec51985997f7119fb2e6d20d61b5327d5740109aa310b410bfb44f354e086f207fcab721e69ae023046c68fb7909f994350a2d1c84d1ae5dff8c00de6d86b7891a6cf90ceea09159402e6e2ed3fa548db28d33146319eefda318201213082011d020101304b303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d4155535452494102086189db18b6ede857300d06096086480165030402010500a066301506092a864886f70d01090331080606678108010101301c06092a864886f70d010905310f170d3233303331373133343031385a302f06092a864886f70d01090431220420eb5dd19b9688751461b3e61c9c80f1e848d91eec210048aca6653279c7c37c76300c06082a8648ce3d04030205000446304402202567959c119ee15d14520eab1b527c2bc493253d6733bbec30295af57e3ceb070220614dcea3ba92499e2212b9cd4159758cd49ae240e74b3e20d8d49183ed1feb09")

	nodes := TlvDecode(sodBytes)

	str := nodes.String()

	if len(str) < 1 {
		t.Errorf("TLV string conversion should yield something")
	}
}
