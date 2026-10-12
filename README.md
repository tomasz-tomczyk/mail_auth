# MailAuth

Checks whether an email really came from who it says. MailAuth verifies DKIM signatures, SPF and DMARC, signs mail with DKIM, and reads and writes `Authentication-Results:` headers. It works on mail received over SMTP and on mail read later over IMAP.

| Standard | What | Here |
|---|---|---|
| RFC 6376, RFC 8301, RFC 8463 | DKIM, its algorithm rules, Ed25519 | Verify and sign |
| RFC 9989 | DMARC, with the DNS tree walk | Yes |
| RFC 7208 | SPF | Yes |
| RFC 8601 | `Authentication-Results:` | Write and parse |
| RFC 8616 | Internationalized domains in DKIM and DMARC | Yes |
| RFC 9990 | DMARC aggregate reports | Parse |

ARC (RFC 8617) is not implemented: the IETF is moving it to Historic, and DKIM2 is meant to replace it.

## Installation

```elixir
def deps do
  [
    {:mail_auth, "~> 0.1"}
  ]
end
```

MailAuth needs Elixir 1.18 or newer. It has no NIFs: it uses OTP's `:crypto`, `:public_key` and `:inet_res`.

## Why

The `From:` line of an email proves nothing. Neither does the `Authentication-Results:` header that the receiving server adds: anyone can write one, and some servers write it without their name. A DKIM signature is part of the message and can still be checked after the message is stored. MailAuth checks it, then checks that the signing domain matches the `From:` domain under the domain's DMARC record. That gives a DMARC pass without trusting any header.

## Usage

### Mail read over IMAP

A help desk or a shared inbox reads mail long after it arrived. There is no client IP, so SPF can't run; DKIM and DMARC can.

```elixir
result = MailAuth.authenticate(raw)

if MailAuth.Result.dmarc_pass?(result) do
  # The From: domain sent this message. Check result.dkim for the
  # :body_length_limit warning before trusting text near the end of the body.
end
```

`raw` is the message exactly as stored, headers and body. Lines end in CRLF; a message with bare LF line endings is read as if each LF were CRLF.

### An SMTP server

An SMTP server, such as one built on `gen_smtp`, knows the client IP, so SPF runs too:

```elixir
result = MailAuth.authenticate(raw, ip: peer_ip, mail_from: from, helo: helo)
header = MailAuth.AuthenticationResults.format(result, "mx.example.com")
# Add the header to the message before delivering it.
```

### DNS

Every check reads DNS through a resolver, chosen with the `:resolver` option:

- `MailAuth.Resolver.Inet`, the default, asks DNS servers with `:inet_res`
- `MailAuth.Resolver.Cached` keeps answers in ETS for their TTL, "no such record" answers too. Start it in your supervision tree when you see much mail from the same domains:

  ```elixir
  children = [{MailAuth.Resolver.Cached, resolver: MailAuth.Resolver.Inet}]
  MailAuth.authenticate(raw, resolver: MailAuth.Resolver.Cached)
  ```

- `MailAuth.Resolver.Static` answers from a map, for your tests:

  ```elixir
  records = %{
    "s1._domainkey.example.com" => [txt: "v=DKIM1; p=MIGfMA0G..."],
    "_dmarc.example.com" => [txt: "v=DMARC1; p=reject"]
  }

  MailAuth.authenticate(raw, resolver: MailAuth.Resolver.Static, records: records)
  ```

### Options

Every function takes:

- `:resolver`: see above
- `:deadline`: milliseconds for the whole call. Default 15000. A check still waiting on DNS at the deadline is `:temperror`, reason `:deadline`
- `:timeout`: milliseconds per DNS query. Default 5000
- `:now`: the time to check signatures against. Default: now

DKIM: `:max_signatures` (default 5), `:min_key_bits` (default 1024), `:allow_sha1` (default `false`).

DMARC: `:organizational_domain`, a function `(domain, opts) -> {:ok, org} | {:error, reason}` used instead of the tree walk, for a caller who wants Public Suffix List answers.

SPF: `:receiver`, the name of your host, for the `%{r}` macro and `Received-SPF:`.

### Signing

```elixir
%{private_key: pem, dns_record: txt, dns_name: name} =
  MailAuth.DKIM.generate_key(:rsa, domain: "example.com", selector: "s1")

# Publish `txt` as a TXT record at `name`, then:
{:ok, signed} = MailAuth.DKIM.sign(raw, domain: "example.com", selector: "s1", private_key: pem)
```

Pass a list of signer options to sign with an RSA and an Ed25519 key at once. `From`, `Subject`, `To` and `Date` are oversigned by default, so no one can add a second one.

## Results

Results use the words of RFC 8601: `:pass`, `:fail`, `:neutral`, `:none`, `:temperror`, `:permerror`, and `:softfail` for SPF. Each result has a reason, when it did not pass, and a list of warnings.

### Reasons

| Check | Reason | Result | Meaning |
|---|---|---|---|
| DKIM | `:malformed_signature` | permerror | A tag can't be read, a tag is repeated, or `b=`/`bh=` is not base64 |
| DKIM | `:missing_tag` | permerror | One of `v`, `a`, `b`, `bh`, `d`, `h`, `s` is missing |
| DKIM | `:unsupported_version` | permerror | `v=` is not `1` |
| DKIM | `:unsupported_algorithm` | permerror | `a=` is not `rsa-sha256`, `ed25519-sha256` or `rsa-sha1` |
| DKIM | `:unsupported_canonicalization` | permerror | `c=` is not `simple` or `relaxed` |
| DKIM | `:unsupported_query_method` | permerror | `q=` does not include `dns/txt` |
| DKIM | `:from_not_signed` | permerror | `h=` does not include `From` |
| DKIM | `:domain_mismatch` | permerror | `i=` is not `d=` or a subdomain of it |
| DKIM | `:invalid_expiry` | permerror | `x=` is before `t=` |
| DKIM | `:expired` | permerror | `x=` is in the past |
| DKIM | `:weak_algorithm` | permerror | `rsa-sha1`, without `allow_sha1: true` |
| DKIM | `:no_key` | permerror | No key record at `<s>._domainkey.<d>` |
| DKIM | `:key_revoked` | permerror | The key record has an empty `p=` |
| DKIM | `:malformed_key` | permerror | The key record or the key can't be read |
| DKIM | `:multiple_keys` | permerror | More than one key record |
| DKIM | `:unsupported_key_type` | permerror | `k=` is not `rsa` or `ed25519` |
| DKIM | `:key_algorithm_mismatch` | permerror | The key type is not the one `a=` names |
| DKIM | `:key_hash_mismatch` | permerror | The key's `h=` does not allow the hash |
| DKIM | `:key_service_mismatch` | permerror | The key's `s=` does not include `email` or `*` |
| DKIM | `:strict_identity_mismatch` | permerror | The key has `t=s` and `i=` is a subdomain of `d=` |
| DKIM | `:key_too_small` | permerror | RSA key under `:min_key_bits` |
| DKIM | `:key_too_large` | permerror | RSA key over 4096 bits |
| DKIM | `:body_length_exceeds` | permerror | `l=` is longer than the body |
| DKIM | `:headers_too_large` | permerror | Over 1000 headers or 1 MB of headers |
| DKIM | `:body_hash_mismatch` | fail | The body changed after signing |
| DKIM | `:signature_mismatch` | fail | A signed header changed, or the signature is wrong |
| DKIM | `:dns_error` | temperror | The key lookup failed |
| DKIM | `:deadline` | temperror | The call ran out of time |
| DKIM | `:too_many_signatures` | none | Past `:max_signatures`, not checked |
| SPF | `:no_client_ip` | none | No `:ip` given, as for mail read over IMAP |
| SPF | `:invalid_ip` | none | `:ip` is not an IP address |
| SPF | `:invalid_domain` | none | The domain is not a valid name |
| SPF | `:no_record` | none | No SPF record |
| SPF | `:no_match` | neutral | No mechanism matched |
| SPF | `:multiple_records` | permerror | More than one SPF record |
| SPF | `:malformed_record` | permerror | The record can't be read |
| SPF | `:too_many_lookups` | permerror | Over 10 terms that cause DNS lookups |
| SPF | `:too_many_void_lookups` | permerror | Over 2 lookups that found nothing |
| SPF | `:too_many_mx` | permerror | Over 10 MX names |
| SPF | `:include_no_record` | permerror | An `include:` target has no SPF record |
| SPF | `:redirect_no_record` | permerror | A `redirect=` target has no SPF record |
| SPF | `:dns_error` | temperror | A lookup failed |
| SPF | `:deadline` | temperror | The call ran out of time |
| DMARC | `:no_record` | none | No DMARC record for the From domain |
| DMARC | `:invalid_record` | none | The record has no valid `p=` and no `rua=` |
| DMARC | `:no_from` | permerror | No `From:` header |
| DMARC | `:multiple_from` | permerror | More than one `From:` header |
| DMARC | `:multiple_authors` | permerror | More than one address in `From:` |
| DMARC | `:invalid_from` | permerror | No domain in the `From:` address |
| DMARC | `:headers_too_large` | permerror | Over 1000 headers or 1 MB of headers |
| DMARC | `:not_aligned` | fail | No DKIM or SPF pass for the From domain |
| DMARC | `:dns_error` | temperror | A lookup failed |
| DMARC | `:deadline` | temperror | The call ran out of time |

### Warnings

| Check | Warning | Meaning |
|---|---|---|
| DKIM | `:from_not_oversigned` | A second `From:` could be added without breaking the signature |
| DKIM | `:body_length_limit` | `l=` is set, so text can be added after the signed part |
| DKIM | `:subject_not_signed`, `:to_not_signed` | The header is not signed |
| DKIM | `:weak_algorithm` | `rsa-sha1` passed because of `allow_sha1: true` |
| SPF | `:ptr_used` | The record uses `ptr`, which RFC 7208 asks domains not to use |
| DMARC | `:missing_policy`, `:invalid_policy` | The record has no valid `p=`, `sp=` or `np=` |
| Authentication-Results | `:no_authserv_id` | The header has no server name, so it is never trusted |
| Authentication-Results | `:malformed` | Part of the header can't be read |

## What a pass means

- **A pass proves the domain, not the person.** For `gmail.com` it means Google says the user signed in. For a domain that relays mail for many people it proves less.
- **DNSSEC is not checked.** Someone who can change DNS answers on the way can fake a pass.
- **Replay.** A real signed email can be sent again by someone else, to someone else, unless `To:` was signed. A pass says the domain wrote it, not that it was meant for this mailbox. The `:to_not_signed` warning helps; if you care, check `To:` and `Date:` yourself.
- **`l=`.** With a body length limit, anyone can add text after the signed part. Look for the `:body_length_limit` warning. Don't sign with `body_length: true`.
- **Mailing lists and forwarding** usually break DKIM. That is a `:fail`, which is the safe outcome.
- **`disposition`** is what the domain asks you to do with a failing message. MailAuth reports it and never acts on it.

## Command-line tools

These are mix tasks, so they work wherever MailAuth is a dependency:

```sh
mix mail_auth.verify message.eml [--ip 192.0.2.1 --mail-from a@example.com --helo mx.example.com] [--json]
mix mail_auth.sign message.eml --domain example.com --selector s1 --key key.pem
mix mail_auth.dmarc example.com
mix mail_auth.spf example.com 192.0.2.1
mix mail_auth.gen_key --domain example.com --selector s1 [--ed25519]
```

`--dns-file records.txt` answers DNS from a file instead of the network, one record per line (`name TYPE value`), to check a message offline.

## Telemetry

MailAuth emits `:telemetry` spans for `[:mail_auth, :authenticate]`, `[:mail_auth, :dkim, :verify]`, `[:mail_auth, :dmarc]`, `[:mail_auth, :spf]` and `[:mail_auth, :dns, :lookup]`, with the results and the time taken. They never include message content or keys.

## Credits

The DKIM code is a port of [go-msgauth](https://github.com/emersion/go-msgauth) (MIT). Its notice is in `LICENSE`.

## License

MIT. See `LICENSE`.
