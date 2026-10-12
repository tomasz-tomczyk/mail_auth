# DNS

Every check reads DNS through a resolver, a module that implements `MailAuth.Resolver`. Pick one with the `:resolver` option.

## Inet

`MailAuth.Resolver.Inet`, the default, asks DNS servers with OTP's `:inet_res`, using EDNS0 so that 2048-bit DKIM keys fit. Pick the servers with `nameservers: [{{192, 0, 2, 53}, 53}]`.

## Cached

`MailAuth.Resolver.Cached` keeps answers in ETS for their TTL, capped at one hour. "No such record" answers are kept too; failures are not.

```elixir
children = [
  {MailAuth.Resolver.Cached, resolver: MailAuth.Resolver.Inet, max_size: 10_000}
]
```

## Static

`MailAuth.Resolver.Static` answers from a map. Use it in tests:

```elixir
records = %{
  "example.com" => [txt: "v=spf1 ip4:192.0.2.0/24 -all", mx: {10, "mx.example.com"}],
  "mx.example.com" => [a: {192, 0, 2, 1}],
  "broken.example" => :temperror
}

MailAuth.SPF.check("192.0.2.1", "a@example.com", "mx.example.com",
  resolver: MailAuth.Resolver.Static,
  records: records
)
```

`MailAuth.Resolver.Static.parse_file/1` reads records from a file, as `mix mail_auth.verify --dns-file` does.

## Limits

DNS answers come from strangers, so everything is bounded:

- `:deadline` (default 15000 ms) for the whole call; a check still waiting at the deadline is `:temperror`, reason `:deadline`
- `:timeout` (default 5000 ms) for each query
- TXT records over 4 KB are ignored
- SPF's lookup limits, and at most 8 queries for a DMARC tree walk

A failure to reach DNS is `:temperror`, never `:fail`.

## Your own resolver

```elixir
defmodule MyResolver do
  @behaviour MailAuth.Resolver

  @impl true
  def lookup(name, :txt, _opts) do
    case MyDNS.txt(name) do
      {:ok, records} -> {:ok, records, 300}
      :nxdomain -> {:error, :nxdomain, 300}
      _ -> {:error, :temperror, 0}
    end
  end

  def lookup(_name, _type, _opts), do: {:error, :temperror, 0}
end
```
