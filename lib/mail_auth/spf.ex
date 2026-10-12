defmodule MailAuth.SPF do
  @moduledoc """
  SPF (RFC 7208): checks that the client IP may send mail for the `MAIL FROM`
  domain.

  SPF needs the IP address of the client that connected, so it is for SMTP
  servers. Mail read later, such as over IMAP, has no trustworthy client IP:
  `Received:` headers are written by the sender and are not read.

  The limits of RFC 7208 section 4.6.4 apply: at most 10 terms that cause DNS
  lookups, at most 2 that find nothing ("void lookups"), and at most 10 names
  from one `mx` or `ptr`. Going over is `:permerror`. The whole check is also
  under `:deadline`.

  ## Options

    * `:receiver`: the name of the host doing the check, for the `%{r}` macro
      and for `received_spf/2`. Default `"unknown"`
    * `:now`: the time for the `%{t}` macro
    * `:resolver`, `:deadline`, `:timeout`: see `MailAuth.Resolver` and `MailAuth`
  """

  import Bitwise

  alias MailAuth.{DNS, Domain}
  alias MailAuth.SPF.{Macro, Record, Result}

  @max_lookups 10
  @max_void_lookups 2
  @max_names 10

  @doc """
  Checks SPF for a client IP, a `MAIL FROM` address and a HELO name.

  `ip` is a tuple or a string. An empty `mail_from` (a bounce) checks the HELO
  name as `postmaster@<helo>`.
  """
  @spec check(:inet.ip_address() | String.t(), String.t() | nil, String.t() | nil, keyword()) ::
          Result.t()
  def check(ip, mail_from, helo, opts \\ []) do
    opts = DNS.start(opts)

    :telemetry.span([:mail_auth, :spf], %{}, fn ->
      result = do_check(ip, mail_from, helo, opts)
      {result, %{result: result.result}}
    end)
  end

  defp do_check(ip, mail_from, helo, opts) do
    helo = helo && String.trim(helo)
    {sender, local, domain} = sender(mail_from, helo)
    identity = if elem(sender(mail_from, nil), 2) == nil, do: :helo, else: :mailfrom
    base = %Result{domain: domain, mail_from: sender, helo: helo, identity: identity}

    case parse_ip(ip) do
      {:ok, ip} ->
        base = %{base | ip: ip |> :inet.ntoa() |> to_string()}

        state = %{
          ip: ip,
          opts: opts,
          lookups: 0,
          voids: 0,
          trace: [],
          warnings: [],
          vars: vars(ip, sender, local, domain, helo, opts)
        }

        {outcome, state} = check_host(domain || "", state, true)

        %{
          base
          | result: outcome.result,
            reason: outcome[:reason],
            mechanism: outcome[:mechanism],
            explanation: outcome[:explanation],
            trace: Enum.reverse(state.trace),
            warnings: Enum.uniq(Enum.reverse(state.warnings))
        }

      :error ->
        %{base | result: :none, reason: :invalid_ip}
    end
  end

  defp sender(mail_from, helo) do
    mail_from =
      (mail_from || "") |> String.trim() |> String.trim_leading("<") |> String.trim_trailing(">")

    case String.split(mail_from, "@") do
      [""] ->
        {"postmaster@" <> (helo || ""), "postmaster", helo}

      [domain] ->
        {"postmaster@" <> domain, "postmaster", domain}

      parts ->
        domain = List.last(parts)
        local = parts |> Enum.drop(-1) |> Enum.join("@")
        local = if local == "", do: "postmaster", else: local
        {local <> "@" <> domain, local, domain}
    end
  end

  defp parse_ip(ip) when is_binary(ip),
    do: ip |> String.to_charlist() |> :inet.parse_strict_address() |> ok_ip()

  defp parse_ip(ip) when is_tuple(ip),
    do: if(:inet.is_ip_address(ip), do: ok_ip({:ok, ip}), else: :error)

  defp parse_ip(_), do: :error

  # An IPv4 address written as IPv6 (::ffff:192.0.2.1) is checked as IPv4.
  defp ok_ip({:ok, {0, 0, 0, 0, 0, 0xFFFF, ab, cd}}),
    do: {:ok, {ab >>> 8, ab &&& 255, cd >>> 8, cd &&& 255}}

  defp ok_ip({:ok, ip}), do: {:ok, ip}
  defp ok_ip(_), do: :error

  defp vars(ip, sender, local, domain, helo, opts) do
    {i, v} =
      case ip do
        {_, _, _, _} ->
          {ip |> Tuple.to_list() |> Enum.join("."), "in-addr"}

        _ ->
          nibbles =
            ip
            |> Tuple.to_list()
            |> Enum.map_join(&(&1 |> Integer.to_string(16) |> String.pad_leading(4, "0")))
            |> String.downcase()
            |> String.graphemes()
            |> Enum.join(".")

          {nibbles, "ip6"}
      end

    now =
      case Keyword.get(opts, :now) do
        nil -> System.os_time(:second)
        %DateTime{} = dt -> DateTime.to_unix(dt)
        n -> n
      end

    %{
      ?s => sender,
      ?l => local,
      ?o => domain || "",
      ?d => domain || "",
      ?i => i,
      ?v => v,
      ?h => helo || "",
      ?c => ip |> :inet.ntoa() |> to_string(),
      ?r => Keyword.get(opts, :receiver, "unknown"),
      ?t => Integer.to_string(now)
    }
  end

  # check_host() of RFC 7208 section 4.
  defp check_host(domain, state, top?) do
    domain = String.trim_trailing(domain, ".")
    state = put_in(state.vars[?d], domain)

    if valid_domain?(domain) do
      case fetch_record(domain, state) do
        {:ok, txt, record} ->
          state = %{state | trace: [{domain, txt} | state.trace]}
          evaluate(record, domain, state, top?)

        {:error, result, reason} ->
          {%{result: result, reason: reason}, state}
      end
    else
      {%{result: :none, reason: :invalid_domain}, state}
    end
  end

  defp valid_domain?(domain) do
    labels = String.split(domain, ".")

    byte_size(domain) in 1..253 and length(labels) >= 2 and
      Enum.all?(labels, &(byte_size(&1) in 1..63)) and
      not String.starts_with?(domain, "[") and
      not Regex.match?(~r/\A[0-9.]+\z/, domain)
  end

  defp fetch_record(domain, state) do
    case DNS.lookup(domain, :txt, state.opts) do
      {:ok, txts} ->
        case Enum.filter(txts, &Record.spf?/1) do
          [] ->
            {:error, :none, :no_record}

          [txt] ->
            case Record.parse(txt) do
              {:ok, record} -> {:ok, txt, record}
              :error -> {:error, :permerror, :malformed_record}
            end

          _ ->
            {:error, :permerror, :multiple_records}
        end

      {:error, reason} when reason in [:nxdomain, :no_data] ->
        {:error, :none, :no_record}

      {:error, :deadline} ->
        {:error, :temperror, :deadline}

      {:error, :temperror} ->
        {:error, :temperror, :dns_error}
    end
  end

  defp evaluate(record, domain, state, top?) do
    case directives(record.directives, domain, state) do
      {:match, qualifier, term, state} ->
        outcome = %{result: qualifier, mechanism: term}
        {maybe_explain(outcome, record, state, top?), state}

      {:error, result, reason, state} ->
        {%{result: result, reason: reason}, state}

      {:nomatch, state} ->
        if record.redirect && not record.has_all? do
          redirect(record.redirect, state, top?)
        else
          {%{result: :neutral, reason: :no_match}, state}
        end
    end
  end

  defp redirect(spec, state, top?) do
    with {:ok, state} <- count_lookup(state) do
      target = expand_domain(spec, state)

      case check_host(target, state, top?) do
        {%{result: :none}, state} -> {%{result: :permerror, reason: :redirect_no_record}, state}
        other -> other
      end
    else
      {:error, reason, state} -> {%{result: :permerror, reason: reason}, state}
    end
  end

  # The exp= of the record that failed, and only at the top or through a
  # redirect, never through an include.
  defp maybe_explain(%{result: :fail} = outcome, %{exp: exp}, state, true) when exp != nil do
    target = expand_domain(exp, state)

    with false <- DNS.expired?(state.opts),
         {:ok, [txt]} <- DNS.lookup(target, :txt, state.opts),
         {:ok, parts} <- Macro.parse(txt, exp: true) do
      Map.put(outcome, :explanation, Macro.expand(parts, vars_with_p(state)))
    else
      _ -> outcome
    end
  end

  defp maybe_explain(outcome, _record, _state, _top?), do: outcome

  defp directives([], _domain, state), do: {:nomatch, state}

  defp directives([{qualifier, mechanism, term} | rest], domain, state) do
    case mechanism(mechanism, domain, state) do
      {:match, state} -> {:match, qualifier, term, state}
      {:nomatch, state} -> directives(rest, domain, state)
      {:error, _result, _reason, _state} = error -> error
    end
  end

  defp mechanism(:all, _domain, state), do: {:match, state}

  defp mechanism({:ip4, net, len}, _domain, state),
    do: {if(in_network?(state.ip, net, len), do: :match, else: :nomatch), state}

  defp mechanism({:ip6, net, len}, _domain, state),
    do: {if(in_network?(state.ip, net, len), do: :match, else: :nomatch), state}

  defp mechanism({:include, spec}, _domain, state) do
    with {:ok, state} <- count_lookup(state) do
      target = expand_domain(spec, state)

      case check_host(target, state, false) do
        {%{result: :pass}, inner} ->
          {:match, restore(inner, state)}

        {%{result: r}, inner} when r in [:fail, :softfail, :neutral] ->
          {:nomatch, restore(inner, state)}

        {%{result: :none}, inner} ->
          {:error, :permerror, :include_no_record, restore(inner, state)}

        {%{result: r, reason: reason}, inner} ->
          {:error, r, reason, restore(inner, state)}
      end
    else
      {:error, reason, state} -> {:error, :permerror, reason, state}
    end
  end

  defp mechanism({:a, spec, v4, v6}, domain, state) do
    with {:ok, state} <- count_lookup(state) do
      target = if spec, do: expand_domain(spec, state), else: domain

      case addresses(target, state) do
        {:ok, ips} -> {match_any(state.ip, ips, v4, v6), state}
        {:void, state} -> void(state)
        {:error, reason, state} -> {:error, :temperror, reason, state}
      end
    else
      {:error, reason, state} -> {:error, :permerror, reason, state}
    end
  end

  defp mechanism({:mx, spec, v4, v6}, domain, state) do
    with {:ok, state} <- count_lookup(state) do
      target = if spec, do: expand_domain(spec, state), else: domain

      case lookup(target, :mx, state) do
        {:ok, mxs} when length(mxs) > @max_names ->
          {:error, :permerror, :too_many_mx, state}

        {:ok, mxs} ->
          mxs
          |> Enum.sort()
          |> Enum.map(&elem(&1, 1))
          |> Enum.reduce_while({:nomatch, state}, fn host, {_, state} ->
            case addresses(host, state) do
              {:ok, ips} ->
                case match_any(state.ip, ips, v4, v6) do
                  :match -> {:halt, {:match, state}}
                  :nomatch -> {:cont, {:nomatch, state}}
                end

              {:void, state} ->
                {:cont, {:nomatch, state}}

              {:error, reason, state} ->
                {:halt, {:error, :temperror, reason, state}}
            end
          end)

        {:void, state} ->
          void(state)

        {:error, reason, state} ->
          {:error, :temperror, reason, state}
      end
    else
      {:error, reason, state} -> {:error, :permerror, reason, state}
    end
  end

  defp mechanism({:ptr, spec}, domain, state) do
    with {:ok, state} <- count_lookup(state) do
      state = %{state | warnings: [:ptr_used | state.warnings]}
      target = if spec, do: expand_domain(spec, state), else: domain

      case validated_names(state) do
        {:ok, names, state} ->
          matched = Enum.any?(names, &Domain.subdomain_of?(&1, String.downcase(target)))
          {if(matched, do: :match, else: :nomatch), state}

        {:void, state} ->
          void(state)
      end
    else
      {:error, reason, state} -> {:error, :permerror, reason, state}
    end
  end

  defp mechanism({:exists, spec}, _domain, state) do
    with {:ok, state} <- count_lookup(state) do
      target = expand_domain(spec, state)

      case lookup(target, :a, state) do
        {:ok, _} -> {:match, state}
        {:void, state} -> void(state)
        {:error, reason, state} -> {:error, :temperror, reason, state}
      end
    else
      {:error, reason, state} -> {:error, :permerror, reason, state}
    end
  end

  # Counters and the trace carry over from an include; the current domain
  # does not.
  defp restore(inner, outer), do: %{inner | vars: outer.vars}

  defp count_lookup(%{lookups: n} = state) when n >= @max_lookups,
    do: {:error, :too_many_lookups, state}

  defp count_lookup(state), do: {:ok, %{state | lookups: state.lookups + 1}}

  defp void(%{voids: n} = state) when n >= @max_void_lookups,
    do: {:error, :permerror, :too_many_void_lookups, %{state | voids: n + 1}}

  defp void(state), do: {:nomatch, %{state | voids: state.voids + 1}}

  defp lookup(name, type, state) do
    case DNS.lookup(name, type, state.opts) do
      {:ok, records} -> {:ok, records}
      {:error, reason} when reason in [:nxdomain, :no_data] -> {:void, state}
      {:error, :deadline} -> {:error, :deadline, state}
      {:error, :temperror} -> {:error, :dns_error, state}
    end
  end

  defp addresses(name, state) do
    type = if tuple_size(state.ip) == 4, do: :a, else: :aaaa
    lookup(name, type, state)
  end

  defp match_any(ip, ips, v4, v6) do
    len = if tuple_size(ip) == 4, do: v4, else: v6
    if Enum.any?(ips, &in_network?(ip, &1, len)), do: :match, else: :nomatch
  end

  defp in_network?(ip, net, len) when tuple_size(ip) == tuple_size(net) do
    bits = if tuple_size(ip) == 4, do: 8, else: 16
    total = tuple_size(ip) * bits
    shift = total - len
    to_int(ip, bits) >>> shift == to_int(net, bits) >>> shift
  end

  defp in_network?(_ip, _net, _len), do: false

  defp to_int(tuple, bits), do: tuple |> Tuple.to_list() |> Enum.reduce(0, &((&2 <<< bits) + &1))

  # The client's names from PTR, keeping only those that resolve back to the
  # client IP, at most 10 (RFC 7208 section 5.5).
  defp validated_names(state) do
    case lookup(reverse_name(state.ip), :ptr, state) do
      {:ok, names} ->
        validated =
          names
          |> Enum.take(@max_names)
          |> Enum.filter(fn name ->
            case addresses(name, state) do
              {:ok, ips} -> match_any(state.ip, ips, 32, 128) == :match
              _ -> false
            end
          end)
          |> Enum.map(&String.downcase(String.trim_trailing(&1, ".")))

        {:ok, validated, state}

      {:void, state} ->
        {:void, state}

      {:error, _reason, state} ->
        {:ok, [], state}
    end
  end

  defp reverse_name({_, _, _, _} = ip),
    do: (ip |> Tuple.to_list() |> Enum.reverse() |> Enum.join(".")) <> ".in-addr.arpa"

  defp reverse_name(ip) do
    nibbles =
      ip
      |> Tuple.to_list()
      |> Enum.map_join(&(&1 |> Integer.to_string(16) |> String.pad_leading(4, "0")))
      |> String.downcase()
      |> String.graphemes()
      |> Enum.reverse()
      |> Enum.join(".")

    nibbles <> ".ip6.arpa"
  end

  defp vars_with_p(state) do
    Map.put(state.vars, ?p, fn ->
      case validated_names(state) do
        {:ok, [_ | _] = names, _} ->
          domain = state.vars[?d]
          Enum.find(names, &Domain.subdomain_of?(&1, domain)) || hd(names)

        _ ->
          "unknown"
      end
    end)
  end

  # Expands a domain-spec. A name over 253 characters loses labels from the
  # left (RFC 7208 section 7.3).
  defp expand_domain(spec, state) do
    spec |> Macro.expand(vars_with_p(state)) |> String.trim_trailing(".") |> truncate()
  end

  defp truncate(name) when byte_size(name) <= 253, do: name

  defp truncate(name) do
    case String.split(name, ".", parts: 2) do
      [_, rest] -> truncate(rest)
      [_] -> name
    end
  end

  @doc """
  Writes the `Received-SPF:` header for a result (RFC 7208 section 9.1),
  without a final line break.

  Options: `:receiver`, the name of the host that did the check.
  """
  @spec received_spf(Result.t(), keyword()) :: String.t()
  def received_spf(%Result{} = r, opts \\ []) do
    receiver = Keyword.get(opts, :receiver, "unknown")

    pairs =
      [
        {"client-ip", r.ip},
        {"envelope-from", r.mail_from},
        {"helo", r.helo},
        {"receiver", receiver},
        {"mechanism", r.mechanism},
        {"problem", r.reason && r.result in [:temperror, :permerror] && Atom.to_string(r.reason)},
        {"identity", r.identity && Atom.to_string(r.identity)}
      ]
      |> Enum.filter(fn {_, v} -> is_binary(v) and v != "" end)
      |> Enum.map_join("; ", fn {k, v} -> k <> "=" <> quote_value(v) end)

    "Received-SPF: #{r.result} (#{comment(r, receiver)}) #{pairs};"
  end

  defp comment(r, receiver) do
    who = "#{receiver}: domain of #{r.mail_from}"

    case r.result do
      :pass ->
        "#{who} designates #{r.ip} as permitted sender"

      :fail ->
        "#{who} does not designate #{r.ip} as permitted sender"

      :softfail ->
        "#{receiver}: transitioning domain of #{r.mail_from} does not designate #{r.ip} as permitted sender"

      :neutral ->
        "#{receiver}: #{r.ip} is neither permitted nor denied by domain of #{r.mail_from}"

      :none ->
        "#{receiver}: domain of #{r.mail_from} does not publish an SPF record"

      :temperror ->
        "#{receiver}: error in processing during lookup of #{r.mail_from}"

      :permerror ->
        "#{receiver}: permanent error in processing domain of #{r.mail_from}"
    end
    |> String.replace(["(", ")", "\\"], "")
  end

  defp quote_value(v) do
    if Regex.match?(~r/\A[A-Za-z0-9!#$%&'*+\-\/=?^_`{|}~.]+\z/, v) and
         not String.contains?(v, ".."),
       do: v,
       else: "\"" <> String.replace(v, ["\\", "\""], &("\\" <> &1)) <> "\""
  end
end
