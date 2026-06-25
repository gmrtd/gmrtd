# Changelog

## [0.40.0](https://github.com/gmrtd/gmrtd/compare/v0.39.0...v0.40.0) (2026-06-25)


### Features

* **verifier:** add offline document verification and DocumentEx CBOR serialisation ([#385](https://github.com/gmrtd/gmrtd/issues/385)) ([2dc6e58](https://github.com/gmrtd/gmrtd/commit/2dc6e58d7bf30e513059a5f30f077309df453331))

## [0.39.0](https://github.com/gmrtd/gmrtd/compare/v0.38.0...v0.39.0) (2026-06-24)


### Features

* **document:** move ApduLog from Session to DocumentEx ([#384](https://github.com/gmrtd/gmrtd/issues/384)) ([9f2860c](https://github.com/gmrtd/gmrtd/commit/9f2860c6b2b9cde54b4b1ffe32afed807a194b93))
* **session:** add CBOR serialization for chip auth evidence ([#381](https://github.com/gmrtd/gmrtd/issues/381)) ([f0f26c0](https://github.com/gmrtd/gmrtd/commit/f0f26c03b9fa3272a982197c424ff285b3e59085))


### Bug Fixes

* **gmrtd-reader:** update template for PACE-CAM and AA struct changes ([#383](https://github.com/gmrtd/gmrtd/issues/383)) ([ef06873](https://github.com/gmrtd/gmrtd/commit/ef06873939e304b5b61bed81a2e33e05d5ec19ca))

## [0.38.0](https://github.com/gmrtd/gmrtd/compare/v0.37.1...v0.38.0) (2026-06-23)


### Features

* **pace:** add PACE-CAM evidence for offline verification ([#379](https://github.com/gmrtd/gmrtd/issues/379)) ([ebba87b](https://github.com/gmrtd/gmrtd/commit/ebba87b375c1c1cb190cceb04f6118cf3d56b8d2))

## [0.37.1](https://github.com/gmrtd/gmrtd/compare/v0.37.0...v0.37.1) (2026-06-22)


### Bug Fixes

* **mobile:** Add Android 16 KB page-size compatible AAR ([#373](https://github.com/gmrtd/gmrtd/issues/373)) ([708ae22](https://github.com/gmrtd/gmrtd/commit/708ae22eff863721419183117493d91b2068aae7))

## [0.37.0](https://github.com/gmrtd/gmrtd/compare/v0.36.0...v0.37.0) (2026-06-19)


### Features

* **activeauth:** capture AA evidence and add offline VerifyEvidence ([#372](https://github.com/gmrtd/gmrtd/issues/372)) ([8f8355e](https://github.com/gmrtd/gmrtd/commit/8f8355eb624d05b1c75249b524f6b8b3a3cd8e34))
* **chipauth:** capture CA evidence and add offline VerifyEvidence ([#370](https://github.com/gmrtd/gmrtd/issues/370)) ([83429f5](https://github.com/gmrtd/gmrtd/commit/83429f54d5991f29975960a8e83fddbb1ea81676))

## [0.36.0](https://github.com/gmrtd/gmrtd/compare/v0.35.0...v0.36.0) (2026-06-16)


### Features

* **document:** add ToCbor/NewDocumentFromCbor for document export/import ([#365](https://github.com/gmrtd/gmrtd/issues/365)) ([369c129](https://github.com/gmrtd/gmrtd/commit/369c12929920601f93ca6a8cdf242127af8ebbb0))

## [0.35.0](https://github.com/gmrtd/gmrtd/compare/v0.34.0...v0.35.0) (2026-06-11)


### Features

* **cms:** update to latest NL CSCA master-list (2026-06-09) (fixes [#361](https://github.com/gmrtd/gmrtd/issues/361)) ([#362](https://github.com/gmrtd/gmrtd/issues/362)) ([b4f0b26](https://github.com/gmrtd/gmrtd/commit/b4f0b2662552c834538d20d8554df24efac6be9b))

## [0.34.0](https://github.com/gmrtd/gmrtd/compare/v0.33.0...v0.34.0) (2026-06-09)


### Features

* **cms:** display full Subject DN (RFC 4514) instead of CN in gmrtd-… ([#359](https://github.com/gmrtd/gmrtd/issues/359)) ([7b84cf3](https://github.com/gmrtd/gmrtd/commit/7b84cf3467b50b8605834c76a3fcfca8f76f684a))

## [0.33.0](https://github.com/gmrtd/gmrtd/compare/v0.32.11...v0.33.0) (2026-06-08)


### Features

* update DE CSCA Master-List (fixes [#355](https://github.com/gmrtd/gmrtd/issues/355)) ([#356](https://github.com/gmrtd/gmrtd/issues/356)) ([9ae5155](https://github.com/gmrtd/gmrtd/commit/9ae51558c5401082ceea294d7464ca5f5bbf2dd1))

## [0.32.11](https://github.com/gmrtd/gmrtd/compare/v0.32.10...v0.32.11) (2026-06-08)


### Bug Fixes

* **cms:** certificate selection fails when SI uses IssuerAndSerialNumber ([#353](https://github.com/gmrtd/gmrtd/issues/353)) ([cfd2102](https://github.com/gmrtd/gmrtd/commit/cfd2102c6d939f6a91b636a139240ac541d9ee23))

## [0.32.10](https://github.com/gmrtd/gmrtd/compare/v0.32.9...v0.32.10) (2026-06-06)


### Bug Fixes

* **security:** gate chip authenticity verdict on passive authentication ([#350](https://github.com/gmrtd/gmrtd/issues/350)) ([002afb7](https://github.com/gmrtd/gmrtd/commit/002afb76df541ec33908163a04b3c9c988ab6bd2))

## [0.32.9](https://github.com/gmrtd/gmrtd/compare/v0.32.8...v0.32.9) (2026-06-06)


### Bug Fixes

* **activeauth:** enforce minimum RSA modulus size (fixes [#346](https://github.com/gmrtd/gmrtd/issues/346)) ([#347](https://github.com/gmrtd/gmrtd/issues/347)) ([3d5a76a](https://github.com/gmrtd/gmrtd/commit/3d5a76abaf9628374a8d8c5359877a9ce6b13242))

## [0.32.8](https://github.com/gmrtd/gmrtd/compare/v0.32.7...v0.32.8) (2026-06-06)


### Bug Fixes

* **cms:** nil-deref panic in BySKI/ByIssuerCountry (fixes [#343](https://github.com/gmrtd/gmrtd/issues/343)) ([#344](https://github.com/gmrtd/gmrtd/issues/344)) ([1ba6f61](https://github.com/gmrtd/gmrtd/commit/1ba6f61e9a997cdb98437a30de6ecc68cd82029f))

## [0.32.7](https://github.com/gmrtd/gmrtd/compare/v0.32.6...v0.32.7) (2026-06-05)


### Bug Fixes

* **tlv:** tlv.Decode unbounded recursion and O(n²) buffer cloning  ([#341](https://github.com/gmrtd/gmrtd/issues/341)) ([5dbbe6e](https://github.com/gmrtd/gmrtd/commit/5dbbe6e30b5c9aa9ae62890bf1bba649a15a6f4d))

## [0.32.6](https://github.com/gmrtd/gmrtd/compare/v0.32.5...v0.32.6) (2026-06-03)


### Bug Fixes

* **tlv:** ParseLength panics on 32-bit builds when long-form length e… ([#338](https://github.com/gmrtd/gmrtd/issues/338)) ([dcd1b90](https://github.com/gmrtd/gmrtd/commit/dcd1b904512aa40a1c7e4bf689da323109f7e8a7))

## [0.32.5](https://github.com/gmrtd/gmrtd/compare/v0.32.4...v0.32.5) (2026-06-03)


### Bug Fixes

* **crypto-utils:** DecodeX962EcPoint returns nil instead of error ([#335](https://github.com/gmrtd/gmrtd/issues/335)) ([fff61a8](https://github.com/gmrtd/gmrtd/commit/fff61a835143e87278a1cfb27d669594a8b3557d))

## [0.32.4](https://github.com/gmrtd/gmrtd/compare/v0.32.3...v0.32.4) (2026-06-02)


### Bug Fixes

* **cms:** enforce sod/certificate validity (fixes [#329](https://github.com/gmrtd/gmrtd/issues/329)) ([#330](https://github.com/gmrtd/gmrtd/issues/330)) ([1b5c48c](https://github.com/gmrtd/gmrtd/commit/1b5c48cc3027f0700ede1bf3b6762f8509aae4ca))

## [0.32.3](https://github.com/gmrtd/gmrtd/compare/v0.32.2...v0.32.3) (2026-06-02)


### Bug Fixes

* **cms:** SOD/Cert validation enhancements (fixes [#326](https://github.com/gmrtd/gmrtd/issues/326)) ([#327](https://github.com/gmrtd/gmrtd/issues/327)) ([a41d338](https://github.com/gmrtd/gmrtd/commit/a41d338a0abda52a9cf8f9c813ef4768e2169c49))

## [0.32.2](https://github.com/gmrtd/gmrtd/compare/v0.32.1...v0.32.2) (2026-06-02)


### Bug Fixes

* **document:** unbounded count parsing for DG11/DG12 names (fixes [#323](https://github.com/gmrtd/gmrtd/issues/323)) ([#324](https://github.com/gmrtd/gmrtd/issues/324)) ([1ad42f6](https://github.com/gmrtd/gmrtd/commit/1ad42f60a128d740df9ab17c411eba8155c545d5))

## [0.32.1](https://github.com/gmrtd/gmrtd/compare/v0.32.0...v0.32.1) (2026-06-02)


### Bug Fixes

* **iso7816:** SM.Decode downgrade attack vuln (fixes [#320](https://github.com/gmrtd/gmrtd/issues/320)) ([#321](https://github.com/gmrtd/gmrtd/issues/321)) ([c949ef0](https://github.com/gmrtd/gmrtd/commit/c949ef02273ef84245908baf3d300b68900eebfd))

## [0.32.0](https://github.com/gmrtd/gmrtd/compare/v0.31.0...v0.32.0) (2026-05-24)


### Features

* add SkipImages option during NFC read ([#318](https://github.com/gmrtd/gmrtd/issues/318)) ([922c41f](https://github.com/gmrtd/gmrtd/commit/922c41f9722474f2d5c43eb9e0c2a704c822d842))

## [0.31.0](https://github.com/gmrtd/gmrtd/compare/v0.30.0...v0.31.0) (2026-05-23)


### Features

* **dg1:** added raw-mrz ([#316](https://github.com/gmrtd/gmrtd/issues/316)) ([bb7d1bd](https://github.com/gmrtd/gmrtd/commit/bb7d1bdb2ce88d1789c5732b21cc52a70f32d323))

## [0.30.0](https://github.com/gmrtd/gmrtd/compare/v0.29.0...v0.30.0) (2026-05-22)


### Features

* **mobile:** Add OidDesc for OID description lookup ([#313](https://github.com/gmrtd/gmrtd/issues/313)) ([050f82a](https://github.com/gmrtd/gmrtd/commit/050f82aa2a1e4e2d8a5302734e8d5d6f0e5118d6))

## [0.29.0](https://github.com/gmrtd/gmrtd/compare/v0.28.0...v0.29.0) (2026-05-21)


### Features

* **mobile:** add SkipPace ([#310](https://github.com/gmrtd/gmrtd/issues/310)) ([a308158](https://github.com/gmrtd/gmrtd/commit/a3081587b3940f5a5bf7f8c751f718fc47e2cb77))
* **mobile:** init CSCA master-list before ReadDocument ([#312](https://github.com/gmrtd/gmrtd/issues/312)) ([78fa0d2](https://github.com/gmrtd/gmrtd/commit/78fa0d2901fe3864144db06d8d7a5064311daad5))

## [0.28.0](https://github.com/gmrtd/gmrtd/compare/v0.27.3...v0.28.0) (2026-05-16)


### Features

* **mobile:** add CountryName helper ([#308](https://github.com/gmrtd/gmrtd/issues/308)) ([e2514df](https://github.com/gmrtd/gmrtd/commit/e2514df5a604f21a9ea5a132ea3316b5564dcc22))

## [0.27.3](https://github.com/gmrtd/gmrtd/compare/v0.27.2...v0.27.3) (2026-05-11)


### Bug Fixes

* add missing checkout for mobile artifact upload ([#304](https://github.com/gmrtd/gmrtd/issues/304)) ([bfe065c](https://github.com/gmrtd/gmrtd/commit/bfe065cf3d52222a130d9ab5d0b54ba321a206d0))

## [0.27.2](https://github.com/gmrtd/gmrtd/compare/v0.27.1...v0.27.2) (2026-05-11)


### Bug Fixes

* ci mobile release artifact creation ([#302](https://github.com/gmrtd/gmrtd/issues/302)) ([a45461d](https://github.com/gmrtd/gmrtd/commit/a45461daaf1ea1ab0caae67d4c105863bc945dd6))

## [0.27.1](https://github.com/gmrtd/gmrtd/compare/v0.27.0...v0.27.1) (2026-05-11)


### Bug Fixes

* test release artifacts ([#300](https://github.com/gmrtd/gmrtd/issues/300)) ([cb74bee](https://github.com/gmrtd/gmrtd/commit/cb74beec68923e02b8e2163a937ab23795f429dc))

## [0.27.0](https://github.com/gmrtd/gmrtd/compare/v0.26.0...v0.27.0) (2026-05-10)


### Features

* **csca:** update NL CSCA Master List (7/5/2026) ([#296](https://github.com/gmrtd/gmrtd/issues/296)) ([099d0fc](https://github.com/gmrtd/gmrtd/commit/099d0fc4d2e98d1c19821bfebaa1a5404ee32d16))

## [0.26.0](https://github.com/gmrtd/gmrtd/compare/v0.25.0...v0.26.0) (2026-05-10)


### Features

* **csca:** update to latest DE Master List (5/5/2026) ([#293](https://github.com/gmrtd/gmrtd/issues/293)) ([aee8204](https://github.com/gmrtd/gmrtd/commit/aee8204ad567a80445c26cfe872fb0a320a8b768))

## [0.25.0](https://github.com/gmrtd/gmrtd/compare/v0.24.0...v0.25.0) (2026-05-10)


### Features

* **csca:** CSCA utility (fixes [#289](https://github.com/gmrtd/gmrtd/issues/289)) ([#290](https://github.com/gmrtd/gmrtd/issues/290)) ([31f3b22](https://github.com/gmrtd/gmrtd/commit/31f3b22dfa2443b7aebaae3aaa2d9de2c432876c))

## [0.24.0](https://github.com/gmrtd/gmrtd/compare/v0.23.1...v0.24.0) (2026-05-03)


### Features

* **reader:** add summary to document session ([#283](https://github.com/gmrtd/gmrtd/issues/283)) ([1d57212](https://github.com/gmrtd/gmrtd/commit/1d57212f1662923f509a5004dcdc1ff34d191f40))

## [0.23.1](https://github.com/gmrtd/gmrtd/compare/v0.23.0...v0.23.1) (2026-05-01)


### Bug Fixes

* **secure-messaging:** prevent panic if protected status (tag99) is in… ([#274](https://github.com/gmrtd/gmrtd/issues/274)) ([62b27c5](https://github.com/gmrtd/gmrtd/commit/62b27c574ecaf3d862bad09c45ae3d1910490693))

## [0.23.0](https://github.com/gmrtd/gmrtd/compare/v0.22.1...v0.23.0) (2026-04-17)


### Features

* **csca:** update DE CSCA Master-List (fixes [#241](https://github.com/gmrtd/gmrtd/issues/241)) ([#242](https://github.com/gmrtd/gmrtd/issues/242)) ([3305b19](https://github.com/gmrtd/gmrtd/commit/3305b19806c190cb7fb4a2a2b83afda5b114fc02))

## [0.22.1](https://github.com/gmrtd/gmrtd/compare/v0.22.0...v0.22.1) (2026-04-08)


### Bug Fixes

* **reader:** EF.DIR read error on US passport (fixes [#226](https://github.com/gmrtd/gmrtd/issues/226)) ([#227](https://github.com/gmrtd/gmrtd/issues/227)) ([cd6f094](https://github.com/gmrtd/gmrtd/commit/cd6f094c93fe24b45f546295e2c5b174f67b9775))

## [0.22.0](https://github.com/gmrtd/gmrtd/compare/v0.21.0...v0.22.0) (2026-04-06)


### Features

* update NL CSCA master-list (fixes [#223](https://github.com/gmrtd/gmrtd/issues/223)) ([#224](https://github.com/gmrtd/gmrtd/issues/224)) ([ec03dae](https://github.com/gmrtd/gmrtd/commit/ec03daee0bb07e84dd5a87f21b29213a72fb5732))

## [0.21.0](https://github.com/gmrtd/gmrtd/compare/v0.20.1...v0.21.0) (2026-04-06)


### Features

* **cms:** Add EC curve fallback (fixes [#220](https://github.com/gmrtd/gmrtd/issues/220)) ([#221](https://github.com/gmrtd/gmrtd/issues/221)) ([32a8809](https://github.com/gmrtd/gmrtd/commit/32a8809a2c45094cac45bef8299c6f1b07f4ef03))

## [0.20.1](https://github.com/gmrtd/gmrtd/compare/v0.20.0...v0.20.1) (2026-03-29)


### Bug Fixes

* resolve incorrect warning about remaining bytes ([#209](https://github.com/gmrtd/gmrtd/issues/209)) ([e314c62](https://github.com/gmrtd/gmrtd/commit/e314c62864aebba027c9538c150a388547e5d797))

## [0.20.0](https://github.com/gmrtd/gmrtd/compare/v0.19.3...v0.20.0) (2026-03-28)


### Features

* update to latest NL CSCA master-list (march 2026) [fixes [#204](https://github.com/gmrtd/gmrtd/issues/204)] ([#205](https://github.com/gmrtd/gmrtd/issues/205)) ([dbaacf0](https://github.com/gmrtd/gmrtd/commit/dbaacf081eee04d8c82e455aa3598ad08916bd2e))

## [0.19.3](https://github.com/gmrtd/gmrtd/compare/v0.19.2...v0.19.3) (2026-03-09)


### Bug Fixes

* IsImage panics with malicious or malformed data [fixes [#198](https://github.com/gmrtd/gmrtd/issues/198)] ([#199](https://github.com/gmrtd/gmrtd/issues/199)) ([72164e7](https://github.com/gmrtd/gmrtd/commit/72164e7a33e1667c0bb476fca1e50e97e29292de))

## [0.19.2](https://github.com/gmrtd/gmrtd/compare/v0.19.1...v0.19.2) (2026-03-03)


### Bug Fixes

* **activeauth:** support DER-encoded ECDSA signatures for AA ([#188](https://github.com/gmrtd/gmrtd/issues/188)) ([43057ff](https://github.com/gmrtd/gmrtd/commit/43057ffc22c1f87a5f821e4a2833ddd764652a5c))

## [0.19.1](https://github.com/gmrtd/gmrtd/compare/v0.19.0...v0.19.1) (2026-03-02)


### Bug Fixes

* change TlvTag type to uint32 for Android builds ([#184](https://github.com/gmrtd/gmrtd/issues/184)) ([ae36932](https://github.com/gmrtd/gmrtd/commit/ae3693266737bed869371525eb3cf90ba32e970b))

## [0.19.0](https://github.com/gmrtd/gmrtd/compare/v0.18.0...v0.19.0) (2026-02-25)


### Features

* update NL CSCA master-list [fixes [#175](https://github.com/gmrtd/gmrtd/issues/175)] ([#176](https://github.com/gmrtd/gmrtd/issues/176)) ([73128bd](https://github.com/gmrtd/gmrtd/commit/73128bd7ed4b0dbb7095d7f066485d50bf678c78))

## [0.18.0](https://github.com/gmrtd/gmrtd/compare/v0.17.3...v0.18.0) (2026-02-01)


### Features

* **gmrtd-reader:** updated style for gmrtd-reader output ([#173](https://github.com/gmrtd/gmrtd/issues/173)) ([af3c7bb](https://github.com/gmrtd/gmrtd/commit/af3c7bb1a836f1ff65ff057b81ebbaa3a019f15c))

## [0.17.3](https://github.com/gmrtd/gmrtd/compare/v0.17.2...v0.17.3) (2026-01-31)


### Bug Fixes

* bump version for tlv hardening changes ([#170](https://github.com/gmrtd/gmrtd/issues/170)) ([967b798](https://github.com/gmrtd/gmrtd/commit/967b79895c6d765f4546b770725c11923812a194))

## [0.17.2](https://github.com/gmrtd/gmrtd/compare/v0.17.1...v0.17.2) (2026-01-26)


### Bug Fixes

* trigger patch release for v0.17.2 ([#165](https://github.com/gmrtd/gmrtd/issues/165)) ([03474d4](https://github.com/gmrtd/gmrtd/commit/03474d44c33c9bc59da9583c18e92be501e85f06))

## [0.17.1](https://github.com/gmrtd/gmrtd/compare/v0.17.0...v0.17.1) (2026-01-17)


### Bug Fixes

* incorrect OIDs and enhanced SecurityInfos UTs (fixes:[#161](https://github.com/gmrtd/gmrtd/issues/161)) ([#162](https://github.com/gmrtd/gmrtd/issues/162)) ([d8e393c](https://github.com/gmrtd/gmrtd/commit/d8e393c40b5d823aecce36ba07d380c31cb70d02))

## [0.17.0](https://github.com/gmrtd/gmrtd/compare/v0.16.0...v0.17.0) (2026-01-15)


### Features

* update DE CSCA master list (20260108) [fixes:[#157](https://github.com/gmrtd/gmrtd/issues/157)] ([#158](https://github.com/gmrtd/gmrtd/issues/158)) ([4c0e802](https://github.com/gmrtd/gmrtd/commit/4c0e802e349411b8dc9f7c037bd94802cbbd3a20))

## [0.16.0](https://github.com/gmrtd/gmrtd/compare/v0.15.3...v0.16.0) (2026-01-15)


### Features

* process other name(s) defined by '0xA0' tag ([#155](https://github.com/gmrtd/gmrtd/issues/155)) ([7d2bedd](https://github.com/gmrtd/gmrtd/commit/7d2beddf4d27fcabc4795966205ea52cca72175e))

## [0.15.3](https://github.com/gmrtd/gmrtd/compare/v0.15.2...v0.15.3) (2026-01-13)


### Bug Fixes

* alternative curves ([#153](https://github.com/gmrtd/gmrtd/issues/153)) ([5b92054](https://github.com/gmrtd/gmrtd/commit/5b920548a5bed6327988302bf3c6e1c7f83c00b5))

## [0.15.2](https://github.com/gmrtd/gmrtd/compare/v0.15.1...v0.15.2) (2026-01-07)


### Bug Fixes

* add version to mobile interface and cmd app ([#146](https://github.com/gmrtd/gmrtd/issues/146)) ([65916f4](https://github.com/gmrtd/gmrtd/commit/65916f4d60586ebd7db64d26323bb2ad5fbfd338))

## [0.15.1](https://github.com/gmrtd/gmrtd/compare/v0.15.0...v0.15.1) (2026-01-02)


### Bug Fixes

* country mappings for hong kong and hungary ([#140](https://github.com/gmrtd/gmrtd/issues/140)) ([56c089f](https://github.com/gmrtd/gmrtd/commit/56c089f902ad8ea57b1fe4ca0c859230eb19b2b8))

## [0.15.0](https://github.com/gmrtd/gmrtd/compare/v0.14.0...v0.15.0) (2025-12-31)


### Features

* update NL CSCA master list (dec 2025) (fixes [#136](https://github.com/gmrtd/gmrtd/issues/136)) ([#137](https://github.com/gmrtd/gmrtd/issues/137)) ([cd7da89](https://github.com/gmrtd/gmrtd/commit/cd7da899f7b476c6aa3e4ba5afe9a38054163fa4))

## [0.14.0](https://github.com/gmrtd/gmrtd/compare/v0.13.0...v0.14.0) (2025-12-17)


### Features

* update DE CSCA master list (fixes [#131](https://github.com/gmrtd/gmrtd/issues/131)) ([#132](https://github.com/gmrtd/gmrtd/issues/132)) ([ca29bdf](https://github.com/gmrtd/gmrtd/commit/ca29bdf44ac248caf457d1790c86b1ad2183a47c))

## [0.13.0](https://github.com/gmrtd/gmrtd/compare/v0.12.4...v0.13.0) (2025-11-30)


### Features

* separate dynamic data from static document ([#120](https://github.com/gmrtd/gmrtd/issues/120)) ([#121](https://github.com/gmrtd/gmrtd/issues/121)) ([7bdf361](https://github.com/gmrtd/gmrtd/commit/7bdf36181b8b2932ebc0bfa7c2096e62d41cd005))

## [0.12.4](https://github.com/gmrtd/gmrtd/compare/v0.12.3...v0.12.4) (2025-11-26)


### Bug Fixes

* **pace:** PACE error on older Ukrainian passports [fixes [#108](https://github.com/gmrtd/gmrtd/issues/108)] ([#109](https://github.com/gmrtd/gmrtd/issues/109)) ([9a73dcf](https://github.com/gmrtd/gmrtd/commit/9a73dcffb02940e547a6209a9b24aa7bd5109b06))

## [0.12.3](https://github.com/gmrtd/gmrtd/compare/v0.12.2...v0.12.3) (2025-11-25)


### Bug Fixes

* correct RSA signature verification for authentication ([#106](https://github.com/gmrtd/gmrtd/issues/106)) ([7694080](https://github.com/gmrtd/gmrtd/commit/7694080a08716f31b3a91333dc0f211098f110c3))

## [0.12.2](https://github.com/gmrtd/gmrtd/compare/v0.12.1...v0.12.2) (2025-11-20)


### Bug Fixes

* **cryptoutils:** preserve leading zeros in RSA public key decryption ([#104](https://github.com/gmrtd/gmrtd/issues/104)) ([e2e435d](https://github.com/gmrtd/gmrtd/commit/e2e435d3e7a5893638d3d29e2fca08dd53675f94))

## [0.12.1](https://github.com/gmrtd/gmrtd/compare/v0.12.0...v0.12.1) (2025-11-17)


### Bug Fixes

* [BUG] Fix for DG2 for GBR passports ([#102](https://github.com/gmrtd/gmrtd/issues/102)) ([83583bd](https://github.com/gmrtd/gmrtd/commit/83583bd6644f31e76c6a433000f61aea6943aeca))

## [0.12.0](https://github.com/gmrtd/gmrtd/compare/v0.11.1...v0.12.0) (2025-11-11)


### Features

* add support for Indonesia 2010 CSCA Series certificates ([#14](https://github.com/gmrtd/gmrtd/issues/14)) ([#97](https://github.com/gmrtd/gmrtd/issues/97)) ([defbabc](https://github.com/gmrtd/gmrtd/commit/defbabc30ec1b2426fe14f1a29f611387a20225c))

## [0.11.1](https://github.com/gmrtd/gmrtd/compare/v0.11.0...v0.11.1) (2025-11-11)


### Bug Fixes

* incomplete image detection ([#94](https://github.com/gmrtd/gmrtd/issues/94)) ([#95](https://github.com/gmrtd/gmrtd/issues/95)) ([2e6844d](https://github.com/gmrtd/gmrtd/commit/2e6844d6f0ce81f625d96aa6100517a6f40a7b72))

## [0.11.0](https://github.com/gmrtd/gmrtd/compare/v0.10.1...v0.11.0) (2025-10-25)


### Features

* update DE CSCA master list (fixes [#90](https://github.com/gmrtd/gmrtd/issues/90)) ([#91](https://github.com/gmrtd/gmrtd/issues/91)) ([f08ef19](https://github.com/gmrtd/gmrtd/commit/f08ef19902c291ee02308c4d73e0f7ce711f5d6e))

## [0.10.1](https://github.com/gmrtd/gmrtd/compare/v0.10.0...v0.10.1) (2025-09-28)


### Bug Fixes

* case insensitive country lookup ([#84](https://github.com/gmrtd/gmrtd/issues/84)) ([2b0abcc](https://github.com/gmrtd/gmrtd/commit/2b0abcc354a31f650a7ad9d8881c9cb16bbcbf50))

## [0.10.0](https://github.com/gmrtd/gmrtd/compare/v0.9.1...v0.10.0) (2025-09-28)


### Features

* align DG2 images with DG7 ([#82](https://github.com/gmrtd/gmrtd/issues/82)) ([73cb65b](https://github.com/gmrtd/gmrtd/commit/73cb65ba014cd8c1ec5b07472ac92e034fb18a43))

## [0.9.1](https://github.com/gmrtd/gmrtd/compare/v0.9.0...v0.9.1) (2025-09-27)


### Bug Fixes

* android library issues ([#77](https://github.com/gmrtd/gmrtd/issues/77)) ([5253e64](https://github.com/gmrtd/gmrtd/commit/5253e64ad29dbe74cb4693427026a3ea197452ac))

## [0.9.0](https://github.com/gmrtd/gmrtd/compare/v0.8.1...v0.9.0) (2025-09-24)


### Features

* moved JSON document retrieval to GetDocumentJson ([#72](https://github.com/gmrtd/gmrtd/issues/72)) ([938f412](https://github.com/gmrtd/gmrtd/commit/938f41224636e56c0714fa3e1477f975484d91e3))

## [0.8.1](https://github.com/gmrtd/gmrtd/compare/v0.8.0...v0.8.1) (2025-09-24)


### Bug Fixes

* update to make JSON field name consistent ([#70](https://github.com/gmrtd/gmrtd/issues/70)) ([a459bc4](https://github.com/gmrtd/gmrtd/commit/a459bc4d1f3d0e3595db203deca2a767a2bc74d1))

## [0.8.0](https://github.com/gmrtd/gmrtd/compare/v0.7.0...v0.8.0) (2025-09-07)


### Features

* [fixes [#67](https://github.com/gmrtd/gmrtd/issues/67)] update DE Master List to Aug 2025 version ([#68](https://github.com/gmrtd/gmrtd/issues/68)) ([7c12bb3](https://github.com/gmrtd/gmrtd/commit/7c12bb30b6fb5460afabcc5613918f1d7191136d))

## [0.7.0](https://github.com/gmrtd/gmrtd/compare/v0.6.1...v0.7.0) (2025-09-04)


### Features

* (ECDSA) Active auth signature validation ([#62](https://github.com/gmrtd/gmrtd/issues/62)) ([468430c](https://github.com/gmrtd/gmrtd/commit/468430c7bd763d6e5903ccd73814b65fb20e064b))

## [0.6.1](https://github.com/gmrtd/gmrtd/compare/v0.6.0...v0.6.1) (2025-08-25)


### Bug Fixes

* only consider EC keys (getIcPubKeyECForCAM) ([#48](https://github.com/gmrtd/gmrtd/issues/48)) ([8906cca](https://github.com/gmrtd/gmrtd/commit/8906cca08c515874730cc8e8ba62594ab48bddf7))

## [0.6.0](https://github.com/gmrtd/gmrtd/compare/v0.5.0...v0.6.0) (2025-08-22)


### Features

* add pcsc-reader app ([#41](https://github.com/gmrtd/gmrtd/issues/41)) ([fe3f726](https://github.com/gmrtd/gmrtd/commit/fe3f7265fede495c525bd67d02ffb69498be7764))

## [0.5.0](https://github.com/gmrtd/gmrtd/compare/v0.4.0...v0.5.0) (2025-08-19)


### Features

* add support for ISO-39794 ([#38](https://github.com/gmrtd/gmrtd/issues/38)) ([ad82044](https://github.com/gmrtd/gmrtd/commit/ad8204401fd827bd91c99eb6fb283620b18c1c1a))

## [0.4.0](https://github.com/gmrtd/gmrtd/compare/v0.3.1...v0.4.0) (2025-08-16)


### Features

* add mobile package ([#35](https://github.com/gmrtd/gmrtd/issues/35)) ([4351f71](https://github.com/gmrtd/gmrtd/commit/4351f71c4cd544b5d44d066c948a2569da6a035d))

## [0.3.1](https://github.com/gmrtd/gmrtd/compare/v0.3.0...v0.3.1) (2025-08-13)


### Bug Fixes

* don't panic in processResponse when bad data length ([#31](https://github.com/gmrtd/gmrtd/issues/31)) ([7c43eeb](https://github.com/gmrtd/gmrtd/commit/7c43eeb381ea253a50e87acf5cac6f7681a10dac))

## [0.3.0](https://github.com/gmrtd/gmrtd/compare/v0.2.0...v0.3.0) (2025-08-10)


### Features

* moved DG hash checks to PassiveAuth (from Reader) ([#27](https://github.com/gmrtd/gmrtd/issues/27)) ([9d81a43](https://github.com/gmrtd/gmrtd/commit/9d81a43ec6d5d072d47c617dab79f059c2da887e))

## [0.2.0](https://github.com/gmrtd/gmrtd/compare/v0.1.1...v0.2.0) (2025-08-04)


### Features

* CSCA master-list enhancements ([#25](https://github.com/gmrtd/gmrtd/issues/25)) ([3a5c3ad](https://github.com/gmrtd/gmrtd/commit/3a5c3adb11646d40d5161f95863de0b56964cceb))


### Bug Fixes

* release-please config ([#22](https://github.com/gmrtd/gmrtd/issues/22)) ([e1d841e](https://github.com/gmrtd/gmrtd/commit/e1d841e3545aaf686c85f63827de50be86b3c69a))

## [0.1.1](https://github.com/gmrtd/gmrtd/compare/v0.1.0...v0.1.1) (2025-08-02)


### Bug Fixes

* release-please config ([#22](https://github.com/gmrtd/gmrtd/issues/22)) ([e1d841e](https://github.com/gmrtd/gmrtd/commit/e1d841e3545aaf686c85f63827de50be86b3c69a))
