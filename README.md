[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=coverage)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![codecov](https://codecov.io/gh/gmrtd/gmrtd/graph/badge.svg?token=DRKVXTREWV)](https://codecov.io/gh/gmrtd/gmrtd)
[![Go Report Card](https://goreportcard.com/badge/github.com/gmrtd/gmrtd)](https://goreportcard.com/report/github.com/gmrtd/gmrtd)

# gmrtd
Go library for reading **Machine Readable Travel Documents (MRTDs)** such as passports and identity cards, as specified by **ICAO Doc 9303**.

This library focuses on NFC protocol handling, access control, LDS parsing, and cryptographic security checks, including passive authentication and chip authentication where supported.

Higher-level concerns such as OCR and UI are intentionally left to the integrator.

## 🔎 Overview

**gmrtd** provides low-level building blocks for reading and authenticating eMRTDs:

- Access Control (BAC and PACE)
- Secure messaging and APDU handling
- LDS parsing (EF.COM, EF.SOD, Data Groups)
- Passive Authentication (SOD verification)
- Chip Authentication (where supported)
- Extended-length APDU support

The library is transport-agnostic and can be used with desktop, mobile, or embedded NFC stacks.

## 🔐 Access Control Support

### Basic Access Control (BAC)
- Legacy access control mechanism
- **MRZ-based key derivation only**
- Used by older passports and some current documents
- Automatically selected when PACE is not available

### Password Authenticated Connection Establishment (PACE)
- Supported as specified in **ICAO Doc 9303**
- Strong, modern access control mechanism
- Supported password types:
  - **MRZ** (Machine Readable Zone)
  - **CAN** (Card Access Number), commonly used by modern ID cards
- Supports multiple PACE variants:
  - ECDH (GM / CAM)
  - AES / 3DES
  - Brainpool and secp elliptic curves

The caller supplies either MRZ or CAN; **gmrtd negotiates and executes the appropriate protocol automatically** based on document capabilities.

# 📦 Features
- ✅ BAC (MRZ)
- ✅ PACE-GM/CAM (MRZ and CAN)
- ✅ Secure messaging
- ✅ LDS parsing (EF.COM, EF.SOD, DGs)
- ✅ Passive Authentication (SOD verification)
- ✅ Chip Authentication (document-dependent)
- ✅ Extended-length APDU support
- ✅ Transport-agnostic design

# ⚠️ Limitations
- ❌ Terminal Authentication (TA) not implemented
- ❌ PACE-IM not implemented
- ❌ No OCR or MRZ extraction
- ❌ Personal data handling and storage are the responsibility of the caller

# 🧪 Demo Application (PC/SC Reader)
A PC/SC demo reader is included in this repository as a Go command: `cmd/gmrtd-reader`.

It:
- Connects to the first available PC/SC reader
- Runs PACE by default (unless `--skipPace` is set)
- Reads and verifies the document (including passive authentication)
- Renders a HTML report (APDU logs + parsed LDS) and opens it in your browser

### Build / run
```bash
go run ./cmd/gmrtd-reader --help
```

### MRZ (BAC or PACE-MRZ)
```bash
go run ./cmd/gmrtd-reader --doc <DOCUMENT_NUMBER> --dob <YYMMDD> --exp <YYMMDD>
```

### CAN (PACE-CAN)
```bash
go run ./cmd/gmrtd-reader --can <CAN>
```

### Useful flags
```bash
# enable debug logging
--debug

# set/cap maximum Le / read size (bytes)
--maxRead 4096

# skip PACE negotiation (forces BAC where possible; mostly for debugging)
--skipPace
```

> Notes:
> - `--doc/--dob/--exp` and `--can` are mutually exclusive.
> - Requires a PC/SC-compatible NFC reader and a working PC/SC stack.

# 📊 Sample Documents
The following documents have been successfully read using gmrtd:

| Country<br/>(Type,Year) | PACE | Chip Authentication | Ext<br/>Len | LDS<br/>Ver |
| --- | --- | --- | --- | --- |
|🇦🇺 Australia<br/>(P,2016)|n/a (BAC)|<sub>AA-rsaEncryption</sub>|Yes|0107|
|🇦🇹 Austria<br/>(P,2023)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-128<br/>brainpoolP256r1</sub>|<sub>CA-ECDH-AES-CBC-CMAC-128<br/>brainpoolP256r1</sub>|Yes|0107|
|🇨🇦 Canada<br/>(PP,2023)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-128<br/>secp384r1</sub>|<sub>CA-ECDH-AES-CBC-CMAC-128<br/>secp384r1</sub>|No|0108|
|🇨🇳 China<br/>(PO,2018)|n/a (BAC)|<sub>AA-rsaEncryption</sub>|No|0107|
|🇫🇮 Finland<br/>(I,2023)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>brainpoolP384r1</sub>|<sub>PACE-ECDH-CAM-AES-CBC-CMAC-256<br/>brainpoolP384r1</sub>|Yes|0108|
|🇫🇮 Finland<br/>(P,2024)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>brainpoolP384r1</sub>|<sub>PACE-ECDH-CAM-AES-CBC-CMAC-256<br/>brainpoolP384r1</sub>|Yes|0108|
|🇫🇷 France<br/>(P,2017)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>secp256r1</sub>|<sub>CA-ECDH-3DES-CBC-CBC<br/>secp256r1</sub>|Yes|0107|
|🇫🇷 France<br/>(ID,2024)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>brainpoolP256r1<br/>PACE-ECDH-IM-AES-CBC-CMAC-256<br/>brainpoolP256r1<br/>_(PACE-IM not supported)_</sub>|<sub>CA-ECDH-AES-CBC-CMAC-256<br/>brainpoolP256r1</sub>|Yes|0108|
|🇩🇪 Germany<br/>(P,2023)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-128<br/>brainpoolP256r1</sub>|<sub>PACE-ECDH-CAM-AES-CBC-CMAC-128<br/>brainpoolP256r1<br/>CA-ECDH-AES-CBC-CMAC-128<br/>brainpoolP256r1</sub>|Yes|0108|
|🇭🇰 Hong Kong (China)<br/>(P,2025)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>brainpoolP256r1</sub>|<sub>AA-ecc<br/>brainpoolP256r1</sub>|Yes|0108|
|🇮🇩 Indonesia<br/>(P,2025)<br/><sub>ℹ️ 2010 CSCA Series</sub>|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>brainpoolP256r1</sub>|<sub>CA-ECDH-AES-CBC-CMAC-256<br/>brainpoolP256r1</sub>|Yes|0107|
|🇲🇾 Malaysia<br/>(P,2023)|n/a (BAC)|<sub>CA-ECDH-3DES-CBC-CBC<br/>brainpoolP256r1</sub>|Yes|0107|
|🇳🇱 Netherlands<br/>(PP,2025)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>brainpoolP320r1</sub>|<sub>CA-ECDH-AES-CBC-CMAC-256<br/>brainpoolP512r1</sub>|Yes|0108|
|🇳🇿 New Zealand<br/>(P,2017)|<sub>PACE-ECDH-GM-3DES-CBC-CBC<br/>brainpoolP256r1</sub>|<sub>AA-rsaEncryption</sub>|No|0107|
|🇵🇭 Philippines<br/>(P,2020)|n/a (BAC)|<sub>AA-rsaEncryption</sub>|Yes|0107|
|🇵🇹 Portugal<br/>(PP,2026)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-128<br/>brainpoolP256r1</sub>|<sub>CA-ECDH-AES-CBC-CMAC-128<br/>brainpoolP256r1</sub>|Yes|0107|
|🇷🇺 Russia<br/>(P,2020)|n/a (BAC)|<sub>CA-ECDH-3DES-CBC-CBC<br/>secp192</sub>|Yes|0107|
|🇸🇬 Singapore<br/>(PA,2023)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>brainpoolP256r1</sub>|⚠️ Cloneable|Yes|0108|
|🇸🇬 Singapore<br/>(PP,2025)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>brainpoolP256r1</sub>|<sub>AA-rsaEncryption</sub>|Yes|0108|
|🇹🇼 Taiwan<br/>(P,2024)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>secp256r1</sub>|⚠️ Cloneable|Yes|0107|
|🇬🇧 United Kingdom<br/>(P,2021)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>secp256r1</sub>|<sub>CA-ECDH-AES-CBC-CMAC-256<br/>secp256r1</sub>|Yes|0108|
|🇺🇸 United States<br/>(P,2021)|n/a (BAC)|⚠️ Cloneable|No|0107|

Notes:
- PACE entries may use MRZ or CAN depending on document type.
- Cloneable reflects the document’s chip feature set, not a gmrtd vulnerability.

# 🔍 Why Some Documents Are “Cloneable”
Some MRTDs do not implement **strong cryptographic anti-cloning mechanisms** (notably **Chip Authentication (CA)** or **Active Authentication (AA)**).
In these cases:
- Chip data is protected only by access control (BAC or PACE) and secure messaging
- If the access secret (MRZ/CAN) is obtained and the chip is read once, data can be copied and replayed
- This is a **document issuer design choice**, not a vulnerability in gmrtd

Cloneability does not imply that the physical document can be trivially forged.

# 🛡 CSCA Trust Stores
For convenience and interoperability testing, gmrtd includes built-in CSCA trust anchors as standard for:
- [Germany (DE)](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.html)
- [Netherlands (NL)](https://www.npkd.nl/masterlist.html)
- [Indonesia – 2010 CSCA series](https://www.imigrasi.go.id/csca)

These defaults can be replaced, extended, or disabled depending on your trust model.

# 📌 Compatibility
- Go: 1.19+
- Transports: PC/SC, Core NFC, Android NFC, custom APDU transceivers
- Platforms: Desktop, mobile, embedded

# 📚 Specifications
- [ICAO Doc 9303 — Machine Readable Travel Documents](https://www.icao.int/publications/pages/publication.aspx?docnum=9303)
- [ISO/IEC 7816-4 — Smart card command interface](https://www.iso.org/obp/ui/#iso:std:iso-iec:7816:-4)

# 🔒 Security & Responsible Use
This library is intended for **legitimate, consent-based MRTD reading**.

Handle personal data in accordance with applicable laws and regulations.

# 🤝 Contributing
Issues and pull requests are welcome.

When reporting document compatibility issues:
- **Do not upload personal data**
- Include document type/year, protocol used, and anonymised logs

# ❤️ Contributors

<a href="https://github.com/gmrtd/gmrtd/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=gmrtd/gmrtd" />
</a>

Made with [contrib.rocks](https://contrib.rocks).
