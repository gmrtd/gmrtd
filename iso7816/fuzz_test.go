package iso7816

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/utils"
)

// real session keys/SSC/wire bytes, reused from TestSecureMessageDecode /
// TestDecodeSmRApduData. SecureMessaging is constructed from plain key bytes, so a
// fuzz harness can fix a known-good session (as if PACE/BAC had already run) and
// fuzz only the untrusted bytes an on-path attacker (or a malicious/cloned chip)
// actually controls: the R-APDU coming back over the contactless channel.

type smFuzzSeed struct {
	alg   cryptoutils.BlockCipherAlg
	ksEnc []byte
	ksMac []byte
	ssc   []byte
}

var smFuzzSeedTDES = smFuzzSeed{
	alg:   cryptoutils.TDES,
	ksEnc: utils.HexToBytes("979EC13B1CBFE9DCD01AB0FED307EAE5"),
	ksMac: utils.HexToBytes("F1CB1F1FB5ADF208806B89DC579DC1F8"),
	ssc:   utils.HexToBytes("887022120C06C227"),
}

var smFuzzSeedAES = smFuzzSeed{
	alg:   cryptoutils.AES,
	ksEnc: utils.HexToBytes("a8e85e938514ec67ae33cda3d43d3c48"),
	ksMac: utils.HexToBytes("27f1adeb705a049a305b0c619b14b9b3"),
	ssc:   utils.HexToBytes("0000000000000000000000000000000b"),
}

func (seed smFuzzSeed) newSecureMessaging(t *testing.T) *SecureMessaging {
	sm, err := NewSecureMessaging(seed.alg, seed.ksEnc, seed.ksMac)
	if err != nil {
		t.Fatalf("NewSecureMessaging error: %s", err)
	}
	if err := sm.SetSSC(seed.ssc); err != nil {
		t.Fatalf("SetSSC error: %s", err)
	}
	return sm
}

func FuzzParseRApdu(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x90, 0x00})
	f.Add([]byte{0x01, 0x02, 0x03, 0x90, 0x00})
	f.Add([]byte{0x6A, 0x82})

	f.Fuzz(func(t *testing.T, data []byte) {
		rapdu, err := ParseRApdu(data)
		if err != nil {
			return
		}
		if rapdu == nil {
			t.Fatalf("ParseRApdu returned nil rapdu with nil error")
		}

		// roundtrip invariant: Encode() must reproduce the original bytes exactly
		if !bytes.Equal(rapdu.Encode(), data) {
			t.Fatalf("Encode() did not reproduce original bytes (data:%x, encoded:%x)", data, rapdu.Encode())
		}
	})
}

// FuzzSecureMessagingDecode fuzzes SecureMessaging.Decode, the entry point that
// parses a full secure-messaging-protected R-APDU received from the chip. A fresh
// SecureMessaging is built per input since Decode mutates the SSC.
func FuzzSecureMessagingDecode(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(utils.HexToBytes("990290008E08FA855A5D4C50A8ED9000"))
	f.Add(utils.HexToBytes("8781e1012fabf9e0655d7e987fd28a8aeb19c9cadd990d49399799ed1fe465bcea56da9ba3024291d40d23d7f1e00485d71faddc6d8c1382e8028dd22efdcc72ed47663d56d20dd6c4b867956fe0507313083ae7fc54fb46133f184febbe13ad6fd3e2616a1f4a829e75ada1a0e443ca738288f6014be8a7745d8259b089e6bee35bcc4bf5b63db5fdd84244f67eca099213b70a861b4487225aa68af684278fceb4cb809de42be3ee95b0e0d72bcdb0ed47cb56efc264e04a9397a90e81ad1d81efa2d14b2ca8ec7bd997f4b1c1fd344d5dee8589c38b227ca4cb35810060a7cc76403e990290008e083eb47ef4fa82afc99000"))
	f.Add(utils.HexToBytes("9000"))
	f.Add(utils.HexToBytes("990290008E080123456789ABCDEF9000")) // valid shape, bad MAC

	f.Fuzz(func(t *testing.T, rApduBytes []byte) {
		sm := smFuzzSeedTDES.newSecureMessaging(t)
		_, _ = sm.Decode(rApduBytes)
	})
}

// FuzzSecureMessagingDecodeSmRApduData fuzzes decodeSmRApduData directly (the
// version-byte check, CBC decrypt and ISO9797 unpad of an SM data object's value),
// bypassing the outer TLV/MAC envelope that gates it in the real Decode() flow —
// this is what actually reaches the decrypt/unpad logic under mutation, since a
// black-box fuzzer can't forge a valid MAC to get there via FuzzSecureMessagingDecode.
func FuzzSecureMessagingDecodeSmRApduData(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(utils.HexToBytes("019ff0ec34f9922651"))
	f.Add(utils.HexToBytes("0142e919c115faf69350b01813d77a9e8d91912a7f717afd073f199070e61b79c6"))
	f.Add(utils.HexToBytes("ff9ff0ec34f9922651")) // bad version byte

	f.Fuzz(func(t *testing.T, encodedData []byte) {
		smTDES := smFuzzSeedTDES.newSecureMessaging(t)
		_, _ = smTDES.decodeSmRApduData(encodedData)

		smAES := smFuzzSeedAES.newSecureMessaging(t)
		_, _ = smAES.decodeSmRApduData(encodedData)
	})
}
