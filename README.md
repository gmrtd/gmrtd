[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=coverage)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=gmrtd_gmrtd&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=gmrtd_gmrtd)
[![codecov](https://codecov.io/gh/gmrtd/gmrtd/graph/badge.svg?token=DRKVXTREWV)](https://codecov.io/gh/gmrtd/gmrtd)
[![codebeat badge](https://codebeat.co/badges/e142e793-5034-4750-9fdd-d2f90740599c)](https://codebeat.co/projects/github-com-gmrtd-gmrtd-main)
[![Go Report Card](https://goreportcard.com/badge/github.com/gmrtd/gmrtd)](https://goreportcard.com/report/github.com/gmrtd/gmrtd)

# gmrtd
Go library for reading Machine Readable Travel Documents (MRTDs), such as Passports and Identity Cards.

As specified by the [International Civil Aviation Organization](https://www.icao.int) (ICAO), in [Doc Series 9303](https://www.icao.int/publications/pages/publication.aspx?docnum=9303).

Demo application for use with a PCSC NFC Reader is available [here](https://github.com/gmrtd/pcsc-reader).

# Sample Documents

The following are sample documents that have been read:

| Country<br/>(Type,Year) | PACE | Chip Authentication | Ext<br/>Len | LDS<br/>Ver |
| --- | --- | --- | --- | --- |
|🇦🇺 Australia<br/>(P,2016)|n/a (BAC)|<sub>AA-rsaEncryption</sub>|Yes|0107|
|🇦🇹 Austria<br/>(P,2023)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-128<br/>brainpoolP256r1</sub>|<sub>CA-ECDH-AES-CBC-CMAC-128<br/>brainpoolP256r1</sub>|Yes|0107|
|🇨🇦 Canada<br/>(PP,2023)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-128<br/>secp384r1</sub>|<sub>CA-ECDH-AES-CBC-CMAC-128<br/>secp384r1</sub>|No|0108|
|🇨🇳 China<br/>(PO,2018)|n/a (BAC)|<sub>AA-rsaEncryption</sub>|No|0107|
|🇫🇮 Finland<br/>(I,2023)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>brainpoolP384r1</sub>|<sub>PACE-ECDH-CAM-AES-CBC-CMAC-256<br/>brainpoolP384r1</sub>|Yes|0108|
|🇫🇮 Finland<br/>(P,2024)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>brainpoolP384r1</sub>|<sub>PACE-ECDH-CAM-AES-CBC-CMAC-256<br/>brainpoolP384r1</sub>|Yes|0108|
|🇫🇷 France<br/>(P,2017)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>secp256r1</sub>|<sub>(Issue #9)<br/>secp256t1</sub>|Yes|0107|
|🇫🇷 France<br/>(ID,2024)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>brainpoolP256r1<br/>PACE-ECDH-IM-AES-CBC-CMAC-256<br/>brainpoolP256r1<br/>_(PACE-IM not supported)_</sub>|<sub>CA-ECDH-AES-CBC-CMAC-256<br/>brainpoolP256r1</sub>|Yes|0108|
|🇩🇪 Germany<br/>(P,2023)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-128<br/>brainpoolP256r1</sub>|<sub>PACE-ECDH-CAM-AES-CBC-CMAC-128<br/>brainpoolP256r1<br/>CA-ECDH-AES-CBC-CMAC-128<br/>brainpoolP256r1</sub>|Yes|0108|
|🇮🇩 Indonesia<br/>(P,2025)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>brainpoolP256r1</sub>|<sub>CA-ECDH-AES-CBC-CMAC-256<br/>brainpoolP256r1</sub>|Yes|0107|
|🇲🇾 Malaysia<br/>(P,2023)|n/a (BAC)|<sub>CA-ECDH-3DES-CBC-CBC<br/>brainpoolP256r1</sub>|Yes|0107|
|🇳🇿 New Zealand<br/>(P,2017)|<sub>PACE-ECDH-GM-3DES-CBC-CBC<br/>brainpoolP256r1</sub>|<sub>AA-rsaEncryption</sub>|No|0107|
|🇵🇭 Philippines<br/>(P,2020)|n/a (BAC)|<sub>AA-rsaEncryption</sub>|Yes|107|
|🇷🇺 Russia<br/>(P,2020)|n/a (BAC)|<sub>CA-ECDH-3DES-CBC-CBC<br/>secp192</sub>|Yes|0107|
|🇸🇬 Singapore<br/>(PA,2023)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>brainpoolP256r1</sub>|⚠️ Cloneable|Yes|0108|
|🇹🇼 Taiwan<br/>(P,2024)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>secp256r1</sub>|⚠️ Cloneable|Yes|0107|
|🇬🇧 United Kingdom<br/>(P,2021)|<sub>PACE-ECDH-GM-AES-CBC-CMAC-256<br/>secp256r1</sub>|<sub>CA-ECDH-AES-CBC-CMAC-256<br/>secp256r1</sub>|Yes|0108|
|🇺🇸 United States<br/>(P,2021)|n/a (BAC)|⚠️ Cloneable|?|0107|

# Contributors

<a href="https://github.com/gmrtd/gmrtd/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=gmrtd/gmrtd" />
</a>

Made with [contrib.rocks](https://contrib.rocks).
