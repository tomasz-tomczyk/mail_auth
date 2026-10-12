# DKIM

DKIM (RFC 6376) adds a signature to a message. The signing domain publishes its public key in DNS, at `<selector>._domainkey.<domain>`. The signature covers the body and a list of headers, so it still checks out after the message is stored.

## Verifying

```elixir
for result <- MailAuth.DKIM.verify(raw) do
  IO.puts("#{result.domain}: #{result.result} #{result.reason}")
end
```

Each signature gets a `MailAuth.DKIM.Result`, in the order they appear. Up to `:max_signatures` (default 5) are checked; the rest are `:none`, reason `:too_many_signatures`.

What is checked:

- the tags: `v=1`, and `a`, `b`, `bh`, `d`, `h`, `s` present; `h=` includes `From`; `i=` is `d=` or a subdomain of it; `x=` is not in the past
- the key: present, not revoked, of the type `a=` names, at least `:min_key_bits` (default 1024) and at most 4096 bits
- the algorithm: `rsa-sha256` and `ed25519-sha256` (RFC 8463). `rsa-sha1` is `:permerror` unless `allow_sha1: true` (RFC 8301)
- the body hash, then the signature

A pass can carry warnings: `:from_not_oversigned`, `:body_length_limit`, `:subject_not_signed`, `:to_not_signed`.

A key with the `t=y` flag gives `testing?: true`. The domain says it is testing DKIM; the result is as computed, and you may choose not to trust it.

## Signing

```elixir
{:ok, signed} =
  MailAuth.DKIM.sign(raw,
    domain: "example.com",
    selector: "s1",
    private_key: File.read!("s1.pem")
  )
```

The defaults: `relaxed/relaxed`, the headers in `MailAuth.DKIM.default_headers/0`, with `From`, `Subject`, `To` and `Date` oversigned. Pass a list of option lists to sign with several keys at once.

`MailAuth.DKIM.signature_header/2` returns the header alone.

## Keys

```elixir
%{private_key: pem, dns_record: txt, dns_name: name} =
  MailAuth.DKIM.generate_key(:ed25519, domain: "example.com", selector: "s2")
```

RSA keys are 2048 bits by default. Ed25519 keys are short, but some receivers don't check them yet, so sign with both when you use Ed25519.
