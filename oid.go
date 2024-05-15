package gmrtd

import (
	"encoding/asn1"
	"log"
)

// OIDs taken from:
//
// 9.2.1 PACEInfo
// 9.2.2 PACEDomainParameterInfo
// 9.2.3 PACE Object Identifier
// 9.2.4 ActiveAuthenticationInfo
// 9.2.5 ChipAuthenticationInfo
// 9.2.6 ChipAuthenticationPublicKeyInfo
// 9.2.7 Chip Authentication Object Identifier
// 9.2.8 TerminalAuthenticationInfo
// 9.2.9 Terminal Authentication Object Identifiers
// 9.2.10 EFDIRInfo

var (
	oidIcao             = asn1.ObjectIdentifier{1, 3, 27}
	oidIcaoMrtdSecurity = asn1.ObjectIdentifier{1, 3, 27, 1, 1}
	// const ldsSecurityObject = id_icao_mrtd_security + ".1"
	oidIcaoMrtdSecurityAaProtocolObject = asn1.ObjectIdentifier{1, 3, 27, 1, 1, 5}
	oidEfDir                            = asn1.ObjectIdentifier{1, 3, 27, 1, 1, 13}

	oidBsiDe           = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7}
	oidBsiDeAlgorithms = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 1}
	// const standardizedDomainParameters = bsi_de_algorithms + ".2"		// TODO - this is what PACE-CAM is using... maybe have common handling
	oidBsiDeProtocols          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2}
	oidBsiDeProtocolsSmartcard = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2}
	oidPk                      = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 1}
	oidPkDh                    = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 1, 1}
	oidPkEcdh                  = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 1, 2}
	oidTa                      = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2}
	// const id_TA_RSA = id_TA + ".1"
	// const id_TA_RSA_PSS_SHA_256 = id_TA_RSA + ".4"
	// const id_TA_RSA_PSS_SHA_512 = id_TA_RSA + ".6"
	// const id_TA_ECDSA = id_TA + ".2"
	// const id_TA_ECDSA_SHA_224 = id_TA_ECDSA + ".2"
	// const id_TA_ECDSA_SHA_256 = id_TA_ECDSA + ".3"
	// const id_TA_ECDSA_SHA_384 = id_TA_ECDSA + ".4"
	// const id_TA_ECDSA_SHA_512 = id_TA_ECDSA + ".5"

	oidCa = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3}

	oidCaDh              = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 1}
	oidCaDh3DesCbcCbc    = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 1, 1}
	oidCaDhAesCbcCmac128 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 1, 2}
	oidCaDhAesCbcCmac192 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 1, 3}
	oidCaDhAesCbcCmac256 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 1, 4}

	oidCaEcdh              = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2}
	oidCaEcdh3DesCbcCbc    = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 1}
	oidCaEcdhAesCbcCmac128 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 2}
	oidCaEcdhAesCbcCmac192 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 3}
	oidCaEcdhAesCbcCmac256 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 4}

	oidPace = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4}

	oidPaceDhGm              = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1}
	oidPaceDhGm3DesCbcCbc    = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 1}
	oidPaceDhGmAesCbcCmac128 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 2}
	oidPaceDhGmAesCbcCmac192 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 3}
	oidPaceDhGmAesCbcCmac256 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 4}

	oidPaceEcdhGm              = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2}
	oidPaceEcdhGm3DesCbcCbc    = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 1}
	oidPaceEcdhGmAesCbcCmac128 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 2}
	oidPaceEcdhGmAesCbcCmac192 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 3}
	oidPaceEcdhGmAesCbcCmac256 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 4}

	oidPaceDhIm              = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 3}
	oidPaceDhIm3DesCbcCbc    = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 1}
	oidPaceDhImAesCbcCmac128 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 2}
	oidPaceDhImAesCbcCmac192 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 3}
	oidPaceDhImAesCbcCmac256 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 4}

	oidPaceEcdhIm              = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 4}
	oidPaceEcdhIm3DesCbcCbc    = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 1}
	oidPaceEcdhImAesCbcCmac128 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 2}
	oidPaceEcdhImAesCbcCmac192 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 3}
	oidPaceEcdhImAesCbcCmac256 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 4}

	oidPaceEcdhCam              = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 6}
	oidPaceEcdhCamAesCbcCmac128 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 6, 2}
	oidPaceEcdhCamAesCbcCmac192 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 6, 3}
	oidPaceEcdhCamAesCbcCmac256 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 6, 4}

	oidSecurityObject = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 3, 2, 1}
)

var (
	oidHashAlgorithmMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidHashAlgorithmSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidHashAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidHashAlgorithmSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidHashAlgorithmSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidHashAlgorithmSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}

	oidLdsSecurityObject = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 1}
)

var (
	oidPrimeField  = asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}
	oidEcPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// determines if 'oid' starts with 'prefix' (but not equal to - i.e. oid != prefix)
func oidHasPrefix(oid asn1.ObjectIdentifier, prefixOid asn1.ObjectIdentifier) bool {
	// oid must be longer than prefix
	if len(oid) <= len(prefixOid) {
		return false
	}

	return prefixOid.Equal(oid[:len(prefixOid)])
}

// gets the raw OID bytes (without the leading tag/length - 0x06,<len>)
func oidBytes(oid asn1.ObjectIdentifier) []byte {
	asn1bytes, err := asn1.Marshal(oid)
	if err != nil {
		log.Panicf("Unable to encode OID []int (%s)", err.Error())
	}

	return TlvDecode(asn1bytes).GetNode(0x06).GetValue()

}

// decodes the raw OID bytes (excluding the tag/length)
func DecodeAsn1objectId(data []byte) (oid asn1.ObjectIdentifier) {
	var dataWithTag []byte

	// wrap data with ASN1 OID tag (0x06)
	dataWithTag = append(dataWithTag, 0x06)
	dataWithTag = append(dataWithTag, byte(len(data)))
	dataWithTag = append(dataWithTag, data...)

	// attempt to parse OID
	if rest, err := asn1.Unmarshal(dataWithTag, &oid); len(rest) > 0 || err != nil {
		log.Panicf("Error parsing ASN1 OID")
	}

	return oid
}

// TODO - replace with OID variable refs
var oid_lookup = map[string]string{
	"0.4.0.127.0.7.1.2":             "bsiEcKeyType",
	oidPk.String():                  "id-PK",
	oidPkDh.String():                "id-PK-DH",
	oidPkEcdh.String():              "id-PK-ECDH",
	oidTa.String():                  "id-TA",
	"0.4.0.127.0.7.2.2.3.2.4":       "id-TA-ECDSA-SHA-256",
	"0.4.0.127.0.7.2.2.4.2.2":       "id-PACE-ECDH-GM-AES-CBC-CMAC-128",
	"0.4.0.127.0.7.2.2.4.2.4":       "id-PACE-ECDH-GM-AES-CBC-CMAC-256",
	oidPrimeField.String():          "prime-field",
	oidEcPublicKey.String():         "id-ecPublicKey",
	"1.2.840.10045.4.3.2":           "ecdsa-with-SHA256",
	"1.2.840.10045.4.3.3":           "ecdsa-with-SHA384",
	"1.2.840.10045.4.3.4":           "ecdsa-with-sha512",
	"1.2.840.113549.1.1.1":          "rsaEncryption",
	"1.2.840.113549.1.1.8":          "id-mgf1",
	"1.2.840.113549.1.1.10":         "id-RSASSA-PSS",
	"1.2.840.113549.1.7.2":          "id-signedData",
	"1.2.840.113549.1.9.3":          "contentType",
	"1.2.840.113549.1.9.4":          "id-messageDigest",
	"1.2.840.113549.1.9.5":          "signing-time",
	"2.5.4.3":                       "commonName",
	"2.5.4.5":                       "serialNumber",
	"2.5.4.6":                       "countryName",
	"2.5.4.7":                       "localityName",
	"2.5.4.8":                       "stateOrProvinceName",
	"2.5.4.10":                      "organizationName",
	"2.5.4.11":                      "organizationalUnitName",
	"2.5.29.15":                     "id-ce-keyUsage",
	"2.5.29.16":                     "privateKeyUsagePeriod",
	"2.5.29.17":                     "subjectAltName",
	"2.5.29.18":                     "id-ce-issuerAltName",
	"2.5.29.31":                     "id-ce-cRLDistributionPoints",
	"2.5.29.32":                     "certificatePolicies",
	"2.5.29.35":                     "authorityKeyIdentifier",
	"2.5.29.14":                     "subjectKeyIdentifier",
	oidHashAlgorithmMD5.String():    "md5",
	oidHashAlgorithmSHA1.String():   "sha1",
	oidHashAlgorithmSHA256.String(): "sha256",
	oidHashAlgorithmSHA384.String(): "sha384",
	oidHashAlgorithmSHA512.String(): "sha512",
	oidHashAlgorithmSHA224.String(): "sha224",
	oidLdsSecurityObject.String():   "ldsSecurityObject",
	"2.23.136.1.1.6.2":              "documentTypeList",

	oidCa.String(): "id-CA",

	oidCaDh.String():              "id-CA-DH",
	oidCaDh3DesCbcCbc.String():    "id-CA-DH-3DES-CBC-CBC",
	oidCaDhAesCbcCmac128.String(): "id-CA-DH-AES-CBC-CMAC-128",
	oidCaDhAesCbcCmac192.String(): "id-CA-DH-AES-CBC-CMAC-192",
	oidCaDhAesCbcCmac256.String(): "id-CA-DH-AES-CBC-CMAC-256",

	oidCaEcdh.String():              "id-CA-ECDH",
	oidCaEcdh3DesCbcCbc.String():    "id-CA-ECDH-3DES-CBC-CBC",
	oidCaEcdhAesCbcCmac128.String(): "id-CA-ECDH-AES-CBC-CMAC-128",
	oidCaEcdhAesCbcCmac192.String(): "id-CA-ECDH-AES-CBC-CMAC-192",
	oidCaEcdhAesCbcCmac256.String(): "id-CA-ECDH-AES-CBC-CMAC-256",

	oidPaceEcdhCam.String():              "id-PACE-ECDH-CAM",
	oidPaceEcdhCamAesCbcCmac128.String(): "id-PACE-ECDH-CAM-AES-CBC-CMAC-128",
	oidPaceEcdhCamAesCbcCmac192.String(): "id-PACE-ECDH-CAM-AES-CBC-CMAC-192",
	oidPaceEcdhCamAesCbcCmac256.String(): "id-PACE-ECDH-CAM-AES-CBC-CMAC-256",

	oidSecurityObject.String(): "id-SecurityObject",
}
