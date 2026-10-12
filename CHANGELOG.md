# Changelog

## Unreleased

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
