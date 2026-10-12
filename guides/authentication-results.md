# Authentication-Results

## Writing

```elixir
result = MailAuth.authenticate(raw, ip: ip, mail_from: from, helo: helo)
MailAuth.AuthenticationResults.format(result, "mx.example.com")
# "Authentication-Results: mx.example.com;\r\n dkim=pass header.d=..."
```

Add it at the top of the message before you deliver it. Remove any `Authentication-Results:` headers that claim to be from your own server first: a sender can write them.

## Reading

```elixir
MailAuth.AuthenticationResults.parse(raw, trusted: ["mx.google.com"])
```

This reads every `Authentication-Results:` header of a message, or one header. Each comes back with its `authserv_id` and `trusted?`, which is true only for the names you list. A header without a server name, as Outlook writes them, is never trusted.

Don't decide anything from an untrusted header. If you can, check DKIM and DMARC yourself with `MailAuth.authenticate/2`; that needs no trust in any header.
