package gmrtd

import (
	"testing"
)

// TODO - these could all be table-based tests...

// tests the Lds/Unicode version when only the document is empty (i.e no EF.COM or EF.SOD)
func TestVersionUnhappyEmptyDoc(t *testing.T) {
	var doc Document

	expLdsVer := ""
	expUnicodeVer := ""

	{
		ldsVersion := doc.LdsVersion()
		if ldsVersion != expLdsVer {
			t.Errorf("Incorrect LdsVersion (Exp:%s, Act:%s)", expLdsVer, ldsVersion)
		}
	}

	{
		unicodeVersion := doc.UnicodeVersion()
		if unicodeVersion != expUnicodeVer {
			t.Errorf("Incorrect UnicodeVersion (Exp:%s, Act:%s)", expUnicodeVer, unicodeVersion)
		}
	}
}

// tests the Lds/Unicode version when both EF.SOD and EF.COM are present
func TestVersionHappyFromSOD(t *testing.T) {
	var doc Document
	var err error

	// modified from EF.COM test (9303-p10) (LdsVer:1234, UnicodeVer:654321)
	efComBytes := HexToBytes("60145F0104313233345F36063635343332315C026175")

	// SG SOD test data (LdsVer:0108, UnicodeVer:040000)
	efSodBytes := HexToBytes("778209C5308209C106092A864886F70D010702A08209B2308209AE020103310D300B0609608648016503040201308201210606678108010101A0820115048201113082010D020101300B06096086480165030402013081EA30250201010420B8531D522AF781EBBA2F78465B5BEAB1FCCE2861DD947316A217A0F31F06598330250201020420D2FC98EFFEAAC17D42987C48F310315086FC920054F900002DF114A79FF2774B30250201030420883155F3A1EA7948BF4A416625C767ED1F4ED2EAED731F143CC8A22CEABC0CB13025020104042010500F4BC7437F061D4CE735AC0C4F35CF71ADB7C5112AAF9B2CCB2C9BD20C3A302502010D0420ADED95A855D5C0AC69599F46C4C464AD2AAB053798AEBE74C69472FF2FFBB0B4302502010E04209CDA75E7B4F6168E6586CCD175C0AAB3E90F47A68D68E922122937414A90622D300E1304303130381306303430303030A08206603082065C30820410A00302010202045FCDC27C304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203060310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C034943413120301E06035504030C1753696E6761706F72652050617373706F72742043412035301E170D3232303632373032333934315A170D3332313132373135313232355A305D310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C03494341311D301B06035504030C1453472044534331302032303232303632372D303130820122300D06092A864886F70D01010105000382010F003082010A0282010100A695EF6E7174AA7428B351D0106D1B31D0CBC40E2D2FEFFA6F6DEF30220648C124856C14006C2B961CFF1D81776E3704A00E0BB243CB72F1776B7F6EB917F5A9450C2D1CBB0574ADD7BB8D75FAE7746D6C622CC0A5314BB5812D680077BD45DDF49F58CF7D5D9294CC8045219C8280F8DDDE95B529C9F4AAAE45150252B5C691C46B78FF58DF1F2D7ACE90E14E0920B6E4524E87E596E232F6B80D0BCBBECA94EDB552E4EAAACA21AE6AE56C0F961836C90E198AED563100B49E1BB93497592B2CE6A61A494CF76219B96FA52675A4FA39C6249FC07665564BEC456CDB9217A6FBFA9AF2E043968B51E551CF70861E5BFA5493F3FFE40FF937CF5B55E50135E70203010001A38201B7308201B3300E0603551D0F0101FF0404030207803015060767810801010602040A30080201003103130150301B0603551D1204143012A410300E310C300A06035504070C03534750301B0603551D1104143012A410300E310C300A06035504070C035347503081E20603551D1F0481DA3081D7305CA05AA058862A68747470733A2F2F706B64646F776E6C6F6164312E6963616F2E696E742F43524C732F5347502E63726C862A68747470733A2F2F706B64646F776E6C6F6164322E6963616F2E696E742F43524C732F5347502E63726C3077A075A073A471306F310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C034943413120301E06035504030C1753696E6761706F72652050617373706F72742043412035310D300B06035504030C0443524C31302B0603551D1004243022800F32303232303632373032333934315A810F32303232313132373135313232355A301F0603551D2304183016801484CD5D8A477755058D4EC97E0D4992322BE1C545301D0603551D0E04160414A91A62A686DF680A934C0B68032BFAAA100638A6304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A203020120038202010027186E71CB7F33B78FD28565EB886A8224BAB30752BDE7C53257360C872DE2E89318C14F0BBCBE8B34D08463F504C5AD11E5603B71F3D075B00FBED8FB16E9C5F9E95221783F9463C67F78CC3BD80D6EB8B523DE1C7EAD4C88F4CE3B799A2F60BDC11919FF9A68698686072740F7AB6B60F4958E29C6D7113BA25FEC02A1852783068847476DC313889D5DF2255097067EDC02E97EECBC2B42C8B3072171540320745994C42BF7F3E67E47DC20859C2BA02E722B22568E26BC8429480EC1C95B1F02A14BEA48CC51961AC8DDD35702CA814530D4C8125762655125D67EA6B38570D779EBFD6C3C53636CB65B92F4AE27632C7EB15588A537E1619BD3125F7F80CB80E53DE0C998AFDCF02D07D1FC6DE140C462A9C868742BD8FB256CF2F231A3DB45D54C407D262B4365A5A84CA4243327A31A792F56AE9376C56FC84E63FFC079E85EEC6B866465EED66D95520448D74B09F20E450F4B6B116E85A2BC9C0DEAF6DC0063841E49E8C17478E67F28DB7451D97AF0B82996094808B14A2AD0523D75ECDEC9B1E44FDD44D821591439B13ED851AE532FE70447E6504F455FB9D5F7E4FDA0736D6C3F5895C6A474CDEF2A2213A698E101FFA89D6325C37E0FBABAE6DBA6064FA33479C7C2055C2B245A609A57DE4B254A4ECA9DA97ECB288510F94BE8DCC76520874E76930FFD61AFAD808374C916E3A08B1F2EF6BE8070816109743182020F3082020B02010130683060310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C034943413120301E06035504030C1753696E6761706F72652050617373706F7274204341203502045FCDC27C300B0609608648016503040201A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420F990482CF40E723640E3B80910805150E5F5E461FC94C147FB47524D0055445D304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201200482010038D6B5B0DBDCB5CBE3C196613EF5A7311BF391AEA6DED3AACC763AF849AE8D166FA627658F051B18FC119E430B9E1578BF6A9ED5CD6978701FB81D26735D623D835233EA8613E0A96226E048A02BCD776742BB5CB4D97008608B140DF58F15E0900FBE433C0A370F99D77D057F19FEF490297FBD525AF0D8D0F4AC64DB54489009D68FABD416237B2C90C7E98402FF04DAA6CAD7D08933A78D26D2FE111643F1B530DE43DF71AE701EF960B273DF6B0B9A664AA01ED4D601A2C2192185E1E8729C386A89DDB47101DDE606DEEFD8F6815D598601FB6943DA2BB5B044FA034C770DF2529D6379A6D5189328E3C04936833E7BBE9E65DEA4CE103D8494EFADB04F")

	expLdsVer := "0108"
	expUnicodeVer := "040000"

	doc.Com, err = NewCOM(efComBytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	doc.Sod, err = NewSOD(efSodBytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	{
		ldsVersion := doc.LdsVersion()
		if ldsVersion != expLdsVer {
			t.Errorf("Incorrect LdsVersion (Exp:%s, Act:%s)", expLdsVer, ldsVersion)
		}
	}

	{
		unicodeVersion := doc.UnicodeVersion()
		if unicodeVersion != expUnicodeVer {
			t.Errorf("Incorrect UnicodeVersion (Exp:%s, Act:%s)", expUnicodeVer, unicodeVersion)
		}
	}
}

// tests the Lds/Unicode version when only EF.COM is present (i.e. no EF.SOD)
func TestVersionHappyFromCOM(t *testing.T) {
	var doc Document
	var err error

	// modified from EF.COM test (9303-p10) (LdsVer:1234, UnicodeVer:654321)
	efComBytes := HexToBytes("60145F0104313233345F36063635343332315C026175")

	expLdsVer := "1234"
	expUnicodeVer := "654321"

	doc.Com, err = NewCOM(efComBytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	{
		ldsVersion := doc.LdsVersion()
		if ldsVersion != expLdsVer {
			t.Errorf("Incorrect LdsVersion (Exp:%s, Act:%s)", expLdsVer, ldsVersion)
		}
	}

	{
		unicodeVersion := doc.UnicodeVersion()
		if unicodeVersion != expUnicodeVer {
			t.Errorf("Incorrect UnicodeVersion (Exp:%s, Act:%s)", expUnicodeVer, unicodeVersion)
		}
	}
}
