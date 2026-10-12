defmodule MailAuth.Resolver.Inet do
  @moduledoc """
  A resolver that asks DNS servers with OTP's `:inet_res`.

  It asks with EDNS0 and a 4096-byte UDP payload, since a 2048-bit DKIM key
  does not fit in a plain 512-byte answer. `:inet_res` retries over TCP when an
  answer comes back truncated.

  Options:

    * `:nameservers`: a list of `{ip_tuple, port}` to ask. The system's
      servers are the default
    * `:timeout`: milliseconds for the query, set by the caller

  A failure to reach DNS, or a timeout, is `:temperror`.
  """

  @behaviour MailAuth.Resolver

  @negative_ttl 300

  @impl true
  def lookup(name, type, opts) do
    res_opts =
      [edns: 0, udp_payload_size: 4096, timeout: Keyword.get(opts, :timeout, 5000)] ++
        nameservers(opts)

    case :inet_res.resolve(String.to_charlist(name), :in, type, res_opts) do
      {:ok, msg} ->
        answers(msg, type)

      {:error, {:nxdomain, msg}} ->
        {:error, :nxdomain, negative_ttl(msg)}

      {:error, :nxdomain} ->
        {:error, :nxdomain, @negative_ttl}

      {:error, {:noquery, msg}} ->
        {:error, :no_data, negative_ttl(msg)}

      _ ->
        {:error, :temperror, 0}
    end
  end

  defp nameservers(opts) do
    case Keyword.fetch(opts, :nameservers) do
      {:ok, servers} -> [nameservers: servers]
      :error -> []
    end
  end

  defp answers(msg, type) do
    rrs =
      for rr <- :inet_dns.msg(msg, :anlist), :inet_dns.rr(rr, :type) == type do
        {:inet_dns.rr(rr, :data), :inet_dns.rr(rr, :ttl)}
      end

    case rrs do
      [] ->
        {:error, :no_data, negative_ttl(msg)}

      _ ->
        ttl = rrs |> Enum.map(&elem(&1, 1)) |> Enum.min()
        {:ok, Enum.map(rrs, fn {data, _} -> convert(type, data) end), ttl}
    end
  end

  defp convert(:txt, strings), do: strings |> Enum.map(&IO.iodata_to_binary/1) |> Enum.join()
  defp convert(:mx, {pref, host}), do: {pref, to_string(host)}
  defp convert(:ptr, host), do: to_string(host)
  defp convert(_type, data), do: data

  defp negative_ttl(msg) do
    case :inet_dns.msg(msg, :nslist) do
      [rr | _] ->
        case :inet_dns.rr(rr, :data) do
          {_mname, _rname, _serial, _refresh, _retry, _expire, minimum} ->
            min(minimum, :inet_dns.rr(rr, :ttl))

          _ ->
            @negative_ttl
        end

      _ ->
        @negative_ttl
    end
  rescue
    _ -> @negative_ttl
  end
end
