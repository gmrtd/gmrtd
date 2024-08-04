package gmrtd

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/utils"
)

func TestGenerateKseed(t *testing.T) {
	// MRZ_information = L898902C<369080619406236
	// 3. Calculate the SHA-1 hash of ‘MRZ_information’:
	// HSHA-1(MRZ_information) = ‘239AB9CB282DAF66231DC5A4DF6BFBAEDF477565’
	// 4. Take the most significant 16 bytes to form the Kseed:
	// Kseed = ‘239AB9CB282DAF66231DC5A4DF6BFBAE’

	mrzi := "L898902C<369080619406236"

	exp := utils.HexToBytes("239AB9CB282DAF66231DC5A4DF6BFBAE")

	out := NewBAC().generateKseed(mrzi)

	if !bytes.Equal(exp, out) {
		t.Errorf("Kseed failed (Exp:%x) (Act:%x)", exp, out)
	}
}

func TestBuildRequest(t *testing.T) {
	// /5. Calculate the basic access keys (KEnc and KMAC) according to Section 9.7.1/Appendix D.1:
	//KEnc = ‘AB94FDECF2674FDFB9B391F85D7F76F2’
	//KMAC = ‘7962D9ECE03D1ACD4C76089DCE131543’
	//
	//1. Request an 8 byte random number from the eMRTD’s contactless IC:
	//RND.IC = ‘4608F91988702212’
	//2. Generate an 8 byte random and a 16 byte random:
	//RND.IFD = ‘781723860C06C226’
	//KIFD = ‘0B795240CB7049B01C19B33E32804F0B’
	//3. Concatenate RND.IFD, RND.IC and KIFD:
	//S = ‘781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B’
	//4. Encrypt S with 3DES key KEnc:
	//EIFD = ‘72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2’
	//5. Compute MAC over EIFD with 3DES key KMAC:
	//MIFD = ‘5F1448EEA8AD90A7’
	//6. Construct command data for EXTERNAL AUTHENTICATE and send command APDU to the eMRTD’s contactless IC:
	//cmd_data = ‘72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A7’

	kEnc := utils.HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F2")
	kMac := utils.HexToBytes("7962D9ECE03D1ACD4C76089DCE131543")

	rndIcc := utils.HexToBytes("4608F91988702212")
	rndIfd := utils.HexToBytes("781723860C06C226")
	kIfd := utils.HexToBytes("0B795240CB7049B01C19B33E32804F0B")

	exp := utils.HexToBytes("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A7")

	out, err := NewBAC().buildRequest(rndIfd, rndIcc, kIfd, kEnc, kMac)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if !bytes.Equal(exp, out) {
		t.Errorf("CmdData mismatch")
	}
}

// BAC worked example, taken from ICAO9303 p11 (D.3 AUTHENTICATION AND ESTABLISHMENT OF SESSION KEY)
func TestDoBAC(t *testing.T) {
	var nfc *iso7816.NfcSession

	{
		var transceiver *iso7816.MockTransceiver = new(iso7816.MockTransceiver)

		// add in expected request/response tuples
		transceiver.AddReqRsp("0084000008", "4608F919887022129000")
		transceiver.AddReqRsp("008200002872C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A728", "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D74499000")

		nfc = iso7816.NewNfcSession(transceiver)
	}

	// setup static randoms for test
	getTestRandomBytesFn := func() func(length int) []byte {
		var idx int

		return func(length int) []byte {
			var out []byte

			switch idx {
			case 0:
				out = utils.HexToBytes("781723860C06C226")
			case 1:
				out = utils.HexToBytes("0B795240CB7049B01C19B33E32804F0B")
			default:
				t.Errorf("Invalid index (idx:%1d)", idx)
			}

			// sanity check that length matches requested amount
			if len(out) != length {
				t.Errorf("Test data length does NOT match amount requested (req:%d, act:%d)", length, len(out))
			}

			idx++

			return out
		}
	}

	var password *Password = NewPasswordMrzi("L898902C", "690806", "940623")

	var bac *BAC = NewBAC()

	// override random-byte generator
	bac.randomBytesFn = getTestRandomBytesFn()

	err := bac.doBAC(nfc, password)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// verify Secure-Messaging was setup correctly
	{
		smExp, err := iso7816.NewSecureMessaging(cryptoutils.TDES, utils.HexToBytes("979EC13B1CBFE9DCD01AB0FED307EAE5"), utils.HexToBytes("F1CB1F1FB5ADF208806B89DC579DC1F8"))
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		smExp.SetSSC(utils.HexToBytes("887022120C06C226"))

		if !nfc.SM.Equal(*smExp) {
			t.Errorf("SecureMessaging differs to expected")
		}
	}
}

func TestDoBACPasswordTypeCAN(t *testing.T) {
	// BAC only supports MRZi passwords, so test with CAN

	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(new(iso7816.MockTransceiver))

	var password *Password = NewPasswordCan("123456")

	var bac *BAC = NewBAC()

	err := bac.doBAC(nfc, password)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// verify SM was NOT setup, as BAC is not supported for password=CAN
	if nfc.SM != nil {
		t.Errorf("SM should not have been setup")
	}
}
