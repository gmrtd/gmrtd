package document

import (
	"testing"

	cms "github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/utils"
)

func TestNewCardSecurityNoData(t *testing.T) {
	if cardSec, err := NewCardSecurity(nil); cardSec != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if cardSec, err := NewCardSecurity([]byte{}); cardSec != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewCardSecurityUnhappyBadData(t *testing.T) {
	var cardSecurityFile []byte = utils.HexToBytes("0608") // invalid data

	cardSecurity, err := NewCardSecurity(cardSecurityFile)

	if err == nil {
		t.Errorf("Error expected")
	}

	if cardSecurity != nil {
		t.Errorf("CardSecurity not expected for error case")
	}
}

func TestNewCardSecurityDE(t *testing.T) {
	var cardSecurityFile []byte = utils.HexToBytes("3082074206092A864886F70D010702A08207333082072F020103310F300D0609608648016503040202050030820147060804007F0007030201A08201390482013531820131300D060804007F00070202020201023012060A04007F000702020302020201020201483012060A04007F0007020204020202010202010D3012060A04007F0007020204060202010202010D301C060904007F000702020302300C060704007F0007010202010D0201483062060904007F0007020201023052300C060704007F0007010202010D03420004614CD88B00821A887869D0060B44A9D18789353E8CF7DFBC3F29F79327DE30B97B1B2DDA0BE77F24AD415C327C7B7AB2E9C10B0258F5BCBF90C01825FBDFDEF702010D3062060904007F0007020201023052300C060704007F0007010202010D034200048488A2DC34B6B36D6C01A8DFBD70A874610C53B32893A1DE3B1C4BBF477EEF3761AA51DFD6B52DA43587E95386FC34FFE178D90086A7D646047C82BEBC27DA3E020148A082049730820493308203F8A003020102020204A8300A06082A8648CE3D0403043041310B3009060355040613024445310D300B060355040A0C0462756E64310C300A060355040B0C036273693115301306035504030C0C637363612D6765726D616E79301E170D3233303130343036303434325A170D3333303730343233353935395A305D310B3009060355040613024445311D301B060355040A0C1442756E646573647275636B6572656920476D6248310C300A060355040513033135323121301F06035504030C18446F63756D656E74205369676E65722050617373706F7274308201B53082014D06072A8648CE3D020130820140020101303C06072A8648CE3D01010231008CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53306404307BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826043004A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C110461041D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C53150231008CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565020101036200042CA852CB9A1CAAAA466256D1CFD678BB7E5D8502DFA6F3FDB287293C32AF9FA77AD3A7FA92E56F608110053121354002198B530BC60AC7050AB98D7F6C475FD50706A4A6207D7A6336CB480B966A3AA64894F7F42B8FB4AC4774C9D6892330FBA382016430820160301F0603551D23041830168014A40A5FC380AE3E59AF1B32D6136AEFEEC8CA35E8301D0603551D0E04160414AF9DD5E6565737A8804B5B4C6F45093D809AA865300E0603551D0F0101FF040403020780302B0603551D1004243022800F32303233303130343036303434325A810F32303233303730343233353935395A30160603551D20040F300D300B060904007F000703010101302D0603551D1104263024821262756E646573647275636B657265692E6465A40E300C310A300806035504070C014430510603551D12044A30488118637363612D6765726D616E79406273692E62756E642E6465861C68747470733A2F2F7777772E6273692E62756E642E64652F63736361A40E300C310A300806035504070C01443015060767810801010602040A3008020100310313015030300603551D1F042930273025A023A021861F687474703A2F2F7777772E6273692E62756E642E64652F637363615F63726C300A06082A8648CE3D0403040381880030818402404846F4A03E17896E9094AF7652C38FE31EC964C2C3A906AF813AABEF5FE4F3156D140E2EF991DC11FD860A4A301B225DE9FD4ED39B4F47AC72CDB88CC63B335902405D4E2895875E603CE2863073BF441D1EC53761CF47E5BC2B9B6BECE4F229712E39002D77B555290FA550DF5F40AA22D7D2A1E89FEB3FEF730AE33C937796E8E3318201313082012D02010130473041310B3009060355040613024445310D300B060355040A0C0462756E64310C300A060355040B0C036273693115301306035504030C0C637363612D6765726D616E79020204A8300D06096086480165030402020500A05A301706092A864886F70D010903310A060804007F0007030201303F06092A864886F70D010904313204300FF966AB1283D22A0046338B734FBAE653622C15FE7538392E0987D87BEE0AB009BA77506E45D964B138E688BE8DA60D300C06082A8648CE3D040303050004663064023025FDE09B7F60E9B8F57413427128E6B9ED29C252E396D0F699A84B90247BDBDCA66BDA66A319423EB1D95D206E6BDAE8023016D075859D63301201E925A55ACCC7D3BC1E4C0457A87F5575821C6345FF1C059DEEF935E8125EA948BAAC7A9EF97199")

	cardSecurity, err := NewCardSecurity(cardSecurityFile)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	} else if cardSecurity == nil {
		t.Errorf("CardSecurity expected")
	}

	if cardSecurity != nil {
		// get the CSCA certificate pool
		var cscaCertPool *cms.CertPool = cms.CscaCertPool()

		var certChain [][]byte

		certChain, err = cardSecurity.SD.SD2.Verify(cscaCertPool)
		if err != nil {
			t.Errorf("Error verifying SignedData: %s", err)
		}

		if len(certChain) != 2 {
			t.Errorf("Cert chain should have 2 certs")
		}
	}

	// TODO - check securityInfos?
}
