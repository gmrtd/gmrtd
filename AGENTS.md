# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

`gmrtd` is a Go library for reading and verifying **Machine Readable Travel
Documents** (passports, ID cards) per **ICAO Doc 9303** — NFC access control
(BAC/PACE), secure messaging, LDS parsing (EF.COM/EF.SOD/Data Groups),
passive authentication, and chip authentication. It's transport-agnostic
(PC/SC, Core NFC, Android NFC, custom transceivers) and ships mobile bindings
via `gomobile`.

**Treat this as security-critical code.** Nearly every parser in this repo
consumes bytes from an untrusted source: an NFC chip, a scanned MRZ, or a
downloaded master list. A malformed/hostile input should produce an `error`,
never a panic, hang, or unbounded allocation. See "Fuzzing" below — this is
not hypothetical, fuzzing has already found and fixed a real DoS in the core
TLV decoder.

## Build, test, lint

Canonical commands are in the `Makefile` — prefer it over ad hoc `go`
invocations when running the full suite:

```bash
make test          # go test ./... (excludes cmd/gmrtd-reader; needs no hardware)
make test-short     # -short, faster
make test-race       # -race -short
make cover           # coverage profile + HTML report
make fmt vet lint    # gofmt -l (fails on diff), go vet, staticcheck if installed
make tidy modverify  # go.mod hygiene
```

For a single package during iteration, plain `go test ./<pkg>/...` and
`go build ./...` are fine. `go vet ./...` and `gofmt -l <files>` must be
clean before considering a change done — CI (`go.yml`) runs
`go test -race ./...` and expects `go build -v ./...` to succeed.

Building the whole module on a clean machine needs `libpcsclite-dev` (see
`go.yml`) because of the PC/SC (`reader`) and mobile packages; the core
parsing/protocol packages (`tlv`, `mrz`, `cms`, `oid`, `iso7816`, `document`,
`activeauth`, `bac`, `chipauth`, `pace`, `passiveauth`, `cryptoutils`) do not
pull in cgo and build fine without it.

Go version: 1.26+ (see `go.mod`, `go-version-file: go.mod` in CI).

## Fuzzing

`.github/workflows/fuzz.yml` runs Go's native fuzzer (`go test -fuzz=...`)
nightly against `FuzzXxx` targets spread across `tlv`, `mrz`, `cms`,
`iso7816`, and `document` (one `<pkg>/fuzz_test.go` per package, separate
from the hand-written `_test.go` files). It's informational-only (doesn't
gate PRs) since each target needs real wall-clock time.

- When adding a new parser that takes attacker-controlled `[]byte`/`string`
  (a new DG, a new file type, anything reachable from chip/file data), add a
  matching `FuzzXxx` harness and a matrix entry in `fuzz.yml`. Seed it with
  `f.Add(...)` using real sample bytes already in that package's tests where
  possible, not synthetic data.
- Don't fuzz a function that's *documented* to panic on bad input as a
  design choice (e.g. `tlv.MustDecode`, `oid.DecodeAsn1objectId`) — that's
  guaranteed, non-actionable noise in nightly CI. Fuzz the safe entry point
  instead, and if the panicking function is reachable from untrusted data
  through some other caller, harden that call site (`recover`) rather than
  changing the documented function's contract.
- A found crash means: reproduce it with `go test -run=FuzzX/<hash>`, fix
  the root cause, add a permanent regression unit test (see
  `tlv.TestDecodeHugeLengthDoesNotOverAllocate` for the pattern), and only
  then consider committing the corpus entry under `testdata/fuzz/<FuzzX>/`.

## Architecture map

Low-level → high-level:

| Package | Role |
|---|---|
| `utils`, `oid`, `iso3166` | Byte/ASN.1-OID/country-code helpers |
| `tlv` | BER-TLV encode/decode — the base parser almost everything else builds on |
| `cms` | CMS SignedData / X.509 certificate parsing & verification (used by SOD) |
| `mrz` | MRZ (TD1/TD2/TD3) parsing |
| `password` | Derives BAC/PACE passwords (MRZi, CAN) — not user-facing "passwords" |
| `iso7816` | APDU (C-APDU/R-APDU) encoding, secure messaging, NFC session I/O |
| `bac`, `pace`, `chipauth`, `activeauth` | ICAO access-control and authentication protocols |
| `document` | LDS data structures: EF.COM/EF.SOD/CardAccess/CardSecurity/EF.DIR, DG1–DG16, CBOR (de)serialisation |
| `passiveauth`, `verifier` | SOD-based passive authentication; offline verification from a serialised document |
| `cryptoutils` | Crypto primitives shared across the above |
| `htmlreport` | Renders the HTML report used by the demo apps |
| `reader` | Orchestrates a full read over a transceiver (PC/SC, mobile, etc.) |
| `mobile` | `gomobile`-bound facade for iOS/Android |
| `cmd/gmrtd-reader` | PC/SC demo reader |
| `cmd/gmrtd-verify` | Offline verifier for a serialised CBOR document |
| `cmd/gmrtd-csca` | CSCA trust-store inspection CLI |

## Conventions

- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `chore:`, `refactor:`, `test:`, ...) — enforced by CI on
  PRs and consumed by `release-please` for versioning/changelog.
- **Tests**: table-driven, one `<file>_test.go` per source file, real
  hex-encoded sample bytes via `utils.HexToBytes("...")` rather than
  synthetic data wherever a real ICAO/document sample is available (many
  test files already carry large real cert/DG hex literals — reuse them
  instead of inventing new ones).
- **Errors, not panics**, at package API boundaries that touch
  chip/file/MRZ input. A function may legitimately panic only when that's
  an explicit, tested, documented contract (`Must*` naming or an equivalent
  doc comment) — and even then, any caller that might reach it with
  untrusted data must guard with `recover`, not assume it can't happen.
- Keep functions simple — several recent commits exist purely to reduce
  cognitive complexity flagged by SonarCloud; don't reintroduce deeply
  nested branching where an early-return or extracted helper would do.
- No comments explaining *what* code does; only *why*, when non-obvious
  (a hidden constraint, a spec citation, a workaround). See package doc
  comments (`// Package x ...`) for the existing style.
