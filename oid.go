package gmrtd

import (
	"encoding/asn1"
	"log"
)

const bsi_de = "0.4.0.127.0.7"

// const bsi_de_algorithms = bsi_de + ".1"
const bsi_de_protocols = bsi_de + ".2"
const bsi_de_protocols_smartcard = bsi_de_protocols + ".2"

//const standardizedDomainParameters = bsi_de_algorithms + ".2"

const id_icao = "1.3.27"
const id_icao_mrtd_security = id_icao + ".1.1"

//const ldsSecurityObject = id_icao_mrtd_security + ".1"

// 9.2.1 PACEInfo
// 9.2.2 PACEDomainParameterInfo
// 9.2.3 PACE Object Identifier

const id_PACE = bsi_de_protocols_smartcard + ".4"

const id_PACE_DH_GM = id_PACE + ".1"
const id_PACE_DH_GM_3DES_CBC_CBC = id_PACE_DH_GM + ".1"
const id_PACE_DH_GM_AES_CBC_CMAC_128 = id_PACE_DH_GM + ".2"
const id_PACE_DH_GM_AES_CBC_CMAC_192 = id_PACE_DH_GM + ".3"
const id_PACE_DH_GM_AES_CBC_CMAC_256 = id_PACE_DH_GM + ".4"

const id_PACE_ECDH_GM = id_PACE + ".2"
const id_PACE_ECDH_GM_3DES_CBC_CBC = id_PACE_ECDH_GM + ".1"
const id_PACE_ECDH_GM_AES_CBC_CMAC_128 = id_PACE_ECDH_GM + ".2"
const id_PACE_ECDH_GM_AES_CBC_CMAC_192 = id_PACE_ECDH_GM + ".3"
const id_PACE_ECDH_GM_AES_CBC_CMAC_256 = id_PACE_ECDH_GM + ".4"

const id_PACE_DH_IM = id_PACE + ".3"
const id_PACE_DH_IM_3DES_CBC_CBC = id_PACE_DH_IM + ".1"
const id_PACE_DH_IM_AES_CBC_CMAC_128 = id_PACE_DH_IM + ".2"
const id_PACE_DH_IM_AES_CBC_CMAC_192 = id_PACE_DH_IM + ".3"
const id_PACE_DH_IM_AES_CBC_CMAC_256 = id_PACE_DH_IM + ".4"

const id_PACE_ECDH_IM = id_PACE + ".4"
const id_PACE_ECDH_IM_3DES_CBC_CBC = id_PACE_ECDH_IM + ".1"
const id_PACE_ECDH_IM_AES_CBC_CMAC_128 = id_PACE_ECDH_IM + ".2"
const id_PACE_ECDH_IM_AES_CBC_CMAC_192 = id_PACE_ECDH_IM + ".3"
const id_PACE_ECDH_IM_AES_CBC_CMAC_256 = id_PACE_ECDH_IM + ".4"

const id_PACE_ECDH_CAM = id_PACE + ".6"
const id_PACE_ECDH_CAM_AES_CBC_CMAC_128 = id_PACE_ECDH_CAM + ".2"
const id_PACE_ECDH_CAM_AES_CBC_CMAC_192 = id_PACE_ECDH_CAM + ".3"
const id_PACE_ECDH_CAM_AES_CBC_CMAC_256 = id_PACE_ECDH_CAM + ".4"

// 9.2.4 ActiveAuthenticationInfo

const id_icao_mrtd_security_aaProtocolObject = id_icao_mrtd_security + ".5"

// 9.2.5 ChipAuthenticationInfo
// 9.2.6 ChipAuthenticationPublicKeyInfo
// 9.2.7 Chip Authentication Object Identifier

const id_PK = bsi_de_protocols_smartcard + ".1"

const id_PK_DH = id_PK + ".1"
const id_PK_ECDH = id_PK + ".2"

const id_CA = bsi_de_protocols_smartcard + ".3"

const id_CA_DH = id_CA + ".1"

//const id_CA_DH_3DES_CBC_CBC = id_CA_DH + ".1"
//const id_CA_DH_AES_CBC_CMAC_128 = id_CA_DH + ".2"
//const id_CA_DH_AES_CBC_CMAC_192 = id_CA_DH + ".3"
//const id_CA_DH_AES_CBC_CMAC_256 = id_CA_DH + ".4"

const id_CA_ECDH = id_CA + ".2"

//const id_CA_ECDH_3DES_CBC_CBC = id_CA_ECDH + ".1"
//const id_CA_ECDH_AES_CBC_CMAC_128 = id_CA_ECDH + ".2"
//const id_CA_ECDH_AES_CBC_CMAC_192 = id_CA_ECDH + ".3"
//const id_CA_ECDH_AES_CBC_CMAC_256 = id_CA_ECDH + ".4"

// 9.2.8 TerminalAuthenticationInfo
// 9.2.9 Terminal Authentication Object Identifiers

const id_TA = bsi_de_protocols_smartcard + ".2"

//const id_TA_RSA = id_TA + ".1"
//const id_TA_RSA_PSS_SHA_256 = id_TA_RSA + ".4"
//const id_TA_RSA_PSS_SHA_512 = id_TA_RSA + ".6"

//const id_TA_ECDSA = id_TA + ".2"
//const id_TA_ECDSA_SHA_224 = id_TA_ECDSA + ".2"
//const id_TA_ECDSA_SHA_256 = id_TA_ECDSA + ".3"
//const id_TA_ECDSA_SHA_384 = id_TA_ECDSA + ".4"
//const id_TA_ECDSA_SHA_512 = id_TA_ECDSA + ".5"

func DecodeAsn1objectId(data []byte) string {
	var oid asn1.ObjectIdentifier

	var dataWithTag []byte

	// wrap data with ASN1 OID tag (0x06)
	dataWithTag = append(dataWithTag, 0x06)
	dataWithTag = append(dataWithTag, byte(len(data)))
	dataWithTag = append(dataWithTag, data...)

	// attempt to parse OID
	if rest, err := asn1.Unmarshal(dataWithTag, &oid); len(rest) > 0 || err != nil {
		log.Panicf("Error parsing ASN1 OID")
	}
	return oid.String()
}

var oid_lookup = map[string]string{
	"0.4.0.127.0.7.1.2":       "bsiEcKeyType",
	"0.4.0.127.0.7.2.2.1.2":   "id-PK-ECDH",
	"0.4.0.127.0.7.2.2.2":     "id-TA",
	"0.4.0.127.0.7.2.2.3.2.4": "id-TA-ECDSA-SHA-256",
	"0.4.0.127.0.7.2.2.4.2.2": "id-PACE-ECDH-GM-AES-CBC-CMAC-128",
	"0.4.0.127.0.7.2.2.4.2.4": "id-PACE-ECDH-GM-AES-CBC-CMAC-256",
	"0.4.0.127.0.7.2.2.4.6.4": "id-PACE-ECDH-CAM-AES-CBC-CMAC-256",
	"1.2.840.10045.1.1":       "prime-field",
	"1.2.840.10045.2.1":       "id-ecPublicKey",
	"1.2.840.10045.4.3.2":     "ecdsa-with-SHA256",
	"1.2.840.10045.4.3.3":     "ecdsa-with-SHA384",
	"1.2.840.113549.1.1.1":    "rsaEncryption",
	"1.2.840.113549.1.1.8":    "id-mgf1",
	"1.2.840.113549.1.1.10":   "id-RSASSA-PSS",
	"1.2.840.113549.1.7.2":    "id-signedData",
	"1.2.840.113549.1.9.3":    "contentType",
	"1.2.840.113549.1.9.4":    "id-messageDigest",
	"1.2.840.113549.1.9.5":    "signing-time",
	"2.5.4.3":                 "commonName",
	"2.5.4.5":                 "serialNumber",
	"2.5.4.6":                 "countryName",
	"2.5.4.7":                 "localityName",
	"2.5.4.8":                 "stateOrProvinceName",
	"2.5.4.10":                "organizationName",
	"2.5.4.11":                "organizationalUnitName",
	"2.5.29.15":               "id-ce-keyUsage",
	"2.5.29.16":               "privateKeyUsagePeriod",
	"2.5.29.17":               "subjectAltName",
	"2.5.29.18":               "id-ce-issuerAltName",
	"2.5.29.31":               "id-ce-cRLDistributionPoints",
	"2.5.29.32":               "certificatePolicies",
	"2.5.29.35":               "authorityKeyIdentifier",
	"2.5.29.14":               "subjectKeyIdentifier",
	"2.16.840.1.101.3.4.2.1":  "id-sha256",
	"2.23.136.1.1.1":          "ldsSecurityObject",
	"2.23.136.1.1.6.2":        "documentTypeList",
}
