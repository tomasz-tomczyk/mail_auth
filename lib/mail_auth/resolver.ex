defmodule MailAuth.Resolver do
  @moduledoc """
  The behaviour for DNS resolvers.

  Every check in this library reads DNS through a resolver, chosen with the
  `:resolver` option. Three come with the library:

    * `MailAuth.Resolver.Inet` (the default) asks DNS servers with `:inet_res`
    * `MailAuth.Resolver.Static` answers from a map, for tests
    * `MailAuth.Resolver.Cached` wraps another resolver with an ETS cache

  ## Answers

  A resolver returns `{:ok, records, ttl}` with:

    * `:txt`: one binary per record, with the strings of one record joined
    * `:a`: IPv4 address tuples, such as `{192, 0, 2, 1}`
    * `:aaaa`: IPv6 address tuples
    * `:mx`: `{preference, exchange}` pairs, the exchange a string
    * `:ptr`: names, as strings

  or `{:error, reason, ttl}`, where `reason` is:

    * `:nxdomain`: the name does not exist
    * `:no_data`: the name exists, with no records of this type
    * `:temperror`: anything else, such as a timeout or a server failure

  The TTL is in seconds. For errors, it says how long the answer may be cached;
  use `0` for `:temperror`.

  Names are given in lowercase A-labels, without a trailing dot. The options
  are the options of the call, so a resolver can read its own from them, and
  `:timeout` holds the milliseconds left for this query.
  """

  @type record_type :: :txt | :a | :aaaa | :mx | :ptr

  @callback lookup(name :: String.t(), type :: record_type(), opts :: keyword()) ::
              {:ok, [term()], ttl :: non_neg_integer()}
              | {:error, :nxdomain | :no_data | :temperror, ttl :: non_neg_integer()}
end
