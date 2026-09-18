package bac

import (
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

// real fixed session (the ICAO 9303 BAC worked example, reused from TestProcessResponse):
// kEnc/kMac derived from a known MRZi, rndIfd/rndIcc from that same session. processResponse
// itself doesn't touch its *BAC receiver's fields, so a zero-value receiver is fine here -
// this fuzzes exactly what an on-path attacker or a malicious/cloned chip controls: the
// EXTERNAL AUTHENTICATE response bytes.
var fuzzBacKEnc = utils.HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F2")
var fuzzBacKMac = utils.HexToBytes("7962D9ECE03D1ACD4C76089DCE131543")
var fuzzBacRndIcc = utils.HexToBytes("4608F91988702212")
var fuzzBacRndIfd = utils.HexToBytes("781723860C06C226")

func FuzzProcessResponse(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(utils.HexToBytes("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449"))
	f.Add(make([]byte, 40)) // right length, all-zero

	var bac BAC

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = bac.processResponse(data, fuzzBacKEnc, fuzzBacKMac, fuzzBacRndIfd, fuzzBacRndIcc)
	})
}
