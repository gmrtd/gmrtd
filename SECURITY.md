# Security Policy

## Supported Versions

Security fixes are made on `main` and released in the next version. Only the
latest release is supported; please upgrade before reporting an issue.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions or pull requests.**

Report them privately via GitHub's private vulnerability reporting:
<https://github.com/gmrtd/gmrtd/security/advisories/new>

Please include:

- the affected package/function and gmrtd version (or commit)
- a description of the issue and its impact
- steps or input to reproduce it (e.g. a crafted TLV/data group, MRZ, or
  master list) — **never include real personal data from a travel document**

This is a volunteer-maintained project, so responses are best-effort. Once a
report is confirmed, a fix will be prepared privately and a GitHub Security
Advisory published alongside the release that contains it, crediting the
reporter unless they prefer otherwise.

## Scope

gmrtd parses data from untrusted sources (NFC chips, scanned MRZs, master
lists), so in-scope issues include anything where malformed or hostile input
causes a panic, hang, unbounded allocation, or a verification result that
should not have been reached (e.g. Passive/Chip/Active Authentication passing
when it should fail).

A document that lacks a security feature (e.g. no Chip/Active Authentication,
so it is cloneable) is an issuer design choice, not a gmrtd vulnerability.
