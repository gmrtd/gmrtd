package pace

import (
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

func TestComputeAuthTokenCbcAesErr(t *testing.T) {
	// Test that error occurs when CBC is used with AES (i.e. !TDES)

	// start with a valid pace-config
	var paceConfig PaceConfig = PaceConfig{oid.OidPaceDhGm3DesCbcCbc, GM, cryptoutils.TDES, 112, CBC, 200}

	// modify to have an invalid cipher
	paceConfig.cipher = cryptoutils.AES

	var key []byte = utils.HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F2")
	var data []byte = utils.HexToBytes("0000000000000000000000000000000000000000000000000000000000000000")

	_, err := paceConfig.computeAuthToken(key, data)

	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestComputeAuthTokenCbcTDesKeyErr(t *testing.T) {
	// Test that error occurs when CBC/TDES key has incorrect length

	// start with a valid pace-config
	var paceConfig PaceConfig = PaceConfig{oid.OidPaceDhGm3DesCbcCbc, GM, cryptoutils.TDES, 112, CBC, 200}

	var key []byte = utils.HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F200") // 1 extra byte
	var data []byte = utils.HexToBytes("0000000000000000000000000000000000000000000000000000000000000000")

	_, err := paceConfig.computeAuthToken(key, data)

	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestComputeAuthTokenCmacTDesErr(t *testing.T) {
	// Test that error occurs when CMAC is used with TDES (i.e. !AES)

	// start with a valid pace-config
	var paceConfig PaceConfig = PaceConfig{oid.OidPaceDhGmAesCbcCmac256, GM, cryptoutils.AES, 256, CMAC, 203}

	// modify to have an invalid cipher
	paceConfig.cipher = cryptoutils.TDES

	var key []byte = utils.HexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	var data []byte = utils.HexToBytes("0000000000000000000000000000000000000000000000000000000000000000")

	_, err := paceConfig.computeAuthToken(key, data)

	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestComputeAuthTokenCmacAesKeyErr(t *testing.T) {
	// Test that error occurs when CMAC/AES key has incorrect length

	// start with a valid pace-config
	var paceConfig PaceConfig = PaceConfig{oid.OidPaceDhGmAesCbcCmac256, GM, cryptoutils.AES, 256, CMAC, 203}

	var key []byte = utils.HexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F00") // 1 extra byte
	var data []byte = utils.HexToBytes("0000000000000000000000000000000000000000000000000000000000000000")

	_, err := paceConfig.computeAuthToken(key, data)

	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestComputeAuthTokenATErr(t *testing.T) {
	// Test that error occurs when an unknown Auth-Token type is specified (not CBC/CMAC)

	// start with a valid pace-config
	var paceConfig PaceConfig = PaceConfig{oid.OidPaceDhGm3DesCbcCbc, GM, cryptoutils.TDES, 112, CBC, 200}

	// modify to have an invalid auth-token
	paceConfig.authToken = 255 // invalid

	var key []byte = utils.HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F2")
	var data []byte = utils.HexToBytes("0000000000000000000000000000000000000000000000000000000000000000")

	_, err := paceConfig.computeAuthToken(key, data)

	if err == nil {
		t.Errorf("Expected error")
	}
}
