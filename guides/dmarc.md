# DMARC

DMARC (RFC 9989) ties DKIM and SPF to the `From:` address. A message passes DMARC when a DKIM signature or the SPF check passed for a domain that matches the `From:` domain.

```elixir
result = MailAuth.authenticate(raw)
result.dmarc.result   # :pass, :fail, :none, :temperror or :permerror
result.dmarc.policy   # what the domain publishes for this address
result.dmarc.disposition
```

## The From domain

The message must have one `From:` header with one address. Several `From:` headers is a known attack: a signature can cover one while a mail app shows another. It is `:permerror`, reason `:multiple_from`.

## Finding the record

MailAuth looks for a TXT record at `_dmarc.<from domain>`, then at each parent domain, up to the top-level domain: at most 8 queries, as RFC 9989's DNS tree walk says. There is no Public Suffix List.

The organizational domain comes from the same walk: the record with `psd=n`, or the domain below a record with `psd=y`, or else the record highest up.

To get the old RFC 7489 behaviour with your own copy of the Public Suffix List, pass `:organizational_domain`:

```elixir
MailAuth.authenticate(raw, organizational_domain: fn domain, _opts -> {:ok, MyPSL.registrable(domain)} end)
```

`MailAuth.DMARC.lookup/2` finds the record for a domain alone.

## Alignment

- relaxed (the default): the DKIM `d=` or the SPF domain has the same organizational domain as the From domain
- strict (`adkim=s`, `aspf=s`): the same domain

## The policy

`p` applies to the From domain itself. Below it, `sp` applies, or `np` when the From domain does not exist in DNS. `t=y` sets `testing?` and steps the disposition down one level.

A record without a valid `p` is read as `p=none` when it has a `rua` address. Otherwise DMARC does not apply: the result is `:none`, reason `:invalid_record`.

## Reports

`MailAuth.DMARC.Report.parse/1` reads aggregate reports (RFC 9990) as XML, gzip or zip.
