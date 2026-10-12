# SPF

SPF (RFC 7208) says which IP addresses may send mail for a domain. It needs the IP of the client that connected, so it is for SMTP servers.

```elixir
result = MailAuth.SPF.check({192, 0, 2, 1}, "sender@example.com", "mx.example.com")
result.result     # :pass, :fail, :softfail, :neutral, :none, :temperror or :permerror
result.mechanism  # the term that decided it, such as "-all"
result.trace      # each record evaluated, through include and redirect
```

An empty `MAIL FROM` (a bounce) checks the HELO name as `postmaster@<helo>`.

All mechanisms, modifiers and macros of RFC 7208 are supported. The limits of section 4.6.4 apply: 10 terms that cause DNS lookups, 2 lookups that find nothing, 10 MX or PTR names. The library passes the RFC 7208 test suite.

`ptr` works, with the warning `:ptr_used`, since the RFC asks domains not to use it.

## Mail read later

Mail read over IMAP has no trustworthy client IP. The `Received:` headers are written by whoever sent the message, so MailAuth does not read them. Without `:ip`, `MailAuth.authenticate/2` gives SPF `:none`, reason `:no_client_ip`, and DMARC relies on DKIM.

## Received-SPF

```elixir
MailAuth.SPF.received_spf(result, receiver: "mx.example.org")
```
