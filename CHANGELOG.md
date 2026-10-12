# Changelog

## Unreleased

## 0.1.1 - 2026-10-12

### Security

- DKIM body canonicalization used memory in proportion to the number of lines in the body. Upgrade from 0.1.0. In 0.1.0, `MailAuth.DKIM.Canonical.body(body, :relaxed)`, an internal function, split the whole body into a list of lines, and `MailAuth.authenticate/2`, `MailAuth.DKIM.verify/2` and `MailAuth.DKIM.sign/2` all call it. A 20 MB message of empty lines took 2 GB of memory and 7 seconds to check. Anyone could send one: it only needs a `DKIM-Signature` with `c=relaxed/relaxed` from a domain with a published key. The signature does not have to be valid. Bodies with bare LF line endings were worse, as each LF counted as a line. Now the body is hashed in one pass. Memory use stays the same however large the body is, and 20 MB takes about 0.3 seconds.
- Several DKIM signatures on one message now share the body hash. They no longer keep a copy of the canonical body each.
- A message with bare LF line endings is no longer copied whole to turn them into CRLF. Only the header block is copied. DKIM reads a bare LF in the body as CRLF.

### Added

- The warning `:bare_lf` in `MailAuth.Result.warnings`, when a line in the header block ends in LF without CR

## 0.1.0 - 2026-10-12

### Added

- `MailAuth.authenticate/2`: DKIM, SPF and DMARC in one call
- DKIM verify and sign (RFC 6376, RFC 8301, RFC 8463), with key generation
- DMARC (RFC 9989), with the DNS tree walk and the `np`, `psd` and `t` tags
- SPF (RFC 7208), with its lookup limits, and the `Received-SPF:` header
- `Authentication-Results:` writing and parsing (RFC 8601)
- DMARC aggregate report parsing (RFC 9990)
- Resolvers: `Inet`, `Static` and `Cached`
- Mix tasks: `mail_auth.verify`, `mail_auth.sign`, `mail_auth.dmarc`, `mail_auth.spf`, `mail_auth.gen_key`
- Telemetry spans
