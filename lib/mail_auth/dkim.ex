defmodule MailAuth.DKIM do
  @moduledoc """
  DKIM signatures (RFC 6376), with the algorithm rules of RFC 8301 and
  Ed25519 keys (RFC 8463).

  `verify/2` checks every `DKIM-Signature` header of a message. `sign/2` adds
  one or more. `generate_key/2` makes a key and the TXT record to publish.

  ## Verify options

    * `:max_signatures`: how many signatures to check, in order. Default 5.
      The rest are `:none`, reason `:too_many_signatures`
    * `:min_key_bits`: the smallest RSA key that can pass. Default 1024
    * `:allow_sha1`: when `true`, an `rsa-sha1` signature can pass, with the
      warning `:weak_algorithm`. Default `false`
    * `:now`: the time to check `x=` against, in Unix seconds or a
      `DateTime`. Default: now
    * `:resolver`, `:deadline`, `:timeout`: see `MailAuth.Resolver` and `MailAuth`

  ## Signer options

    * `:domain` (required): the signing domain, `d=`
    * `:selector` (required): the selector, `s=`
    * `:private_key` (required): PEM, a decoded `:public_key` record, or
      `{:ed25519, seed}`
    * `:algorithm`: `:rsa_sha256` or `:ed25519_sha256`. Default: from the key
    * `:canonicalization`: default `{:relaxed, :relaxed}`
    * `:headers`: the header names to sign. Each is signed as many times as
      it appears. Default: `default_headers/0`
    * `:oversign`: names listed once more than they appear, so no one can
      add another. Default `["From", "Subject", "To", "Date"]`
    * `:identity`: the `i=` tag
    * `:expires_in`: seconds until the signature expires, for `x=`
    * `:body_length`: when `true`, sets `l=` to the length of the body.
      Unsafe: anyone can add text after the signed part. Default `false`
    * `:now`: the signing time, for `t=`
  """

  alias MailAuth.{DNS, Domain, Message, Tags}
  alias MailAuth.DKIM.{Canonical, Key, Result}

  @default_headers ~w(From To Cc Subject Date Message-ID Reply-To In-Reply-To References
    MIME-Version Content-Type Content-Transfer-Encoding List-Id List-Unsubscribe
    List-Unsubscribe-Post)
  @default_oversign ~w(From Subject To Date)
  @required_tags ~w(v a b bh d h s)

  @doc "The headers signed by default."
  @spec default_headers() :: [String.t()]
  def default_headers, do: @default_headers

  @doc """
  Checks every `DKIM-Signature` header of `raw`, top to bottom.

  Returns one result per signature, in the order they appear. A message with
  no signature gives `[]`.
  """
  @spec verify(binary(), keyword()) :: [Result.t()]
  def verify(raw, opts \\ []) when is_binary(raw) do
    opts = DNS.start(opts)

    :telemetry.span([:mail_auth, :dkim, :verify], %{}, fn ->
      results = do_verify(raw, opts)
      {results, %{results: Enum.map(results, & &1.result)}}
    end)
  end

  defp do_verify(raw, opts) do
    case Message.parse(raw) do
      {:ok, msg} ->
        max = Keyword.get(opts, :max_signatures, 5)
        signatures = Message.get_all(msg, "dkim-signature")
        {checked, skipped} = Enum.split(signatures, max)

        {results, _cache} =
          Enum.map_reduce(checked, %{}, fn sig, cache -> verify_one(msg, sig, opts, cache) end)

        results ++
          Enum.map(skipped, fn sig ->
            %{describe(sig, opts) | result: :none, reason: :too_many_signatures}
          end)

      {:error, reason} ->
        [%Result{result: :permerror, reason: reason}]
    end
  end

  # Reads what it can from a signature, for the result, without judging it.
  defp describe(raw_sig, opts) do
    case Tags.parse(Message.value(raw_sig)) do
      {:ok, tags} -> describe_tags(Map.new(tags), opts)
      {:error, _} -> %Result{}
    end
  end

  defp describe_tags(tags, _opts) do
    domain = tags |> Map.get("d", "") |> Tags.strip_whitespace() |> Domain.to_ascii!()

    %Result{
      domain: if(domain == "", do: nil, else: domain),
      selector: tags |> Map.get("s") |> strip() |> ascii_or_nil(),
      identity: identity(tags, domain),
      algorithm: algorithm(Map.get(tags, "a")),
      canonicalization: canonicalization(Map.get(tags, "c")),
      signed_headers:
        case Map.fetch(tags, "h") do
          {:ok, h} -> h |> Tags.colon_list() |> Enum.map(&String.downcase/1)
          :error -> []
        end,
      signed_at: tags |> Map.get("t") |> parse_time(),
      expires_at: tags |> Map.get("x") |> parse_time(),
      body_length: tags |> Map.get("l") |> parse_int()
    }
  end

  defp strip(nil), do: nil
  defp strip(s), do: Tags.strip_whitespace(s)

  defp ascii_or_nil(nil), do: nil
  defp ascii_or_nil(""), do: nil
  defp ascii_or_nil(s), do: Domain.to_ascii!(s)

  defp identity(tags, domain) do
    case Map.fetch(tags, "i") do
      {:ok, i} ->
        i = Tags.strip_whitespace(i)

        case String.split(i, "@") |> Enum.reverse() do
          [dom | local] when local != [] ->
            (local |> Enum.reverse() |> Enum.join("@")) <> "@" <> Domain.to_ascii!(dom)

          _ ->
            i
        end

      :error ->
        if domain == "", do: nil, else: "@" <> domain
    end
  end

  defp algorithm(nil), do: nil

  defp algorithm(a) do
    case a |> Tags.strip_whitespace() |> String.downcase() do
      "rsa-sha256" -> :rsa_sha256
      "ed25519-sha256" -> :ed25519_sha256
      "rsa-sha1" -> :rsa_sha1
      _ -> nil
    end
  end

  defp canonicalization(nil), do: {:simple, :simple}

  defp canonicalization(c) do
    case c |> Tags.strip_whitespace() |> String.downcase() |> String.split("/") do
      [h] -> with {:ok, h} <- canon(h), do: {h, :simple}, else: (_ -> nil)
      [h, b] -> with {:ok, h} <- canon(h), {:ok, b} <- canon(b), do: {h, b}, else: (_ -> nil)
      _ -> nil
    end
  end

  defp canon("simple"), do: {:ok, :simple}
  defp canon("relaxed"), do: {:ok, :relaxed}
  defp canon(_), do: :error

  defp parse_time(nil), do: nil

  defp parse_time(s) do
    with n when is_integer(n) <- parse_int(s),
         {:ok, dt} <- DateTime.from_unix(n) do
      dt
    else
      _ -> nil
    end
  end

  defp parse_int(nil), do: nil

  defp parse_int(s) do
    s = Tags.strip_whitespace(s)

    if s != "" and byte_size(s) <= 76 and Regex.match?(~r/\A[0-9]+\z/, s),
      do: String.to_integer(s),
      else: nil
  end

  defp verify_one(msg, raw_sig, opts, cache) do
    with {:ok, tags} <- sig_tags(raw_sig) do
      result = describe_tags(tags, opts)

      case check(msg, raw_sig, tags, result, opts, cache) do
        {:ok, result, cache} -> {result, cache}
        {:error, kind, reason, result, cache} -> {%{result | result: kind, reason: reason}, cache}
      end
    else
      {:error, reason} -> {%{describe(raw_sig, opts) | result: :permerror, reason: reason}, cache}
    end
  end

  defp sig_tags(raw_sig) do
    case Tags.parse(Message.value(raw_sig)) do
      {:ok, tags} -> {:ok, Map.new(tags)}
      {:error, _} -> {:error, :malformed_signature}
    end
  end

  defp check(msg, raw_sig, tags, result, opts, cache) do
    perm = fn reason -> {:error, :permerror, reason, result, cache} end

    with :ok <- required_tags(tags),
         :ok <- version(tags),
         {:ok, algorithm} <- ok_or(result.algorithm, :unsupported_algorithm),
         {:ok, {hc, bc}} <- ok_or(result.canonicalization, :unsupported_canonicalization),
         {:ok, domain} <- ok_or(result.domain, :malformed_signature),
         {:ok, selector} <- ok_or(result.selector, :malformed_signature),
         :ok <- from_signed(result.signed_headers),
         :ok <- identity_in_domain(result.identity, domain),
         :ok <- numbers(tags, result),
         :ok <- times(result, opts),
         :ok <- query_method(tags),
         {:ok, body_hash} <- base64(tags["bh"]),
         {:ok, signature} <- base64(tags["b"]),
         :ok <- sha1_allowed(algorithm, opts) do
      result = %{result | algorithm: algorithm}

      case fetch_key(selector, domain, opts) do
        {:ok, key} ->
          result = %{result | key_bits: key.bits, testing?: "y" in key.flags}

          with :ok <- key_matches(key, algorithm, result, domain, opts) do
            verify_crypto(msg, raw_sig, result, {hc, bc}, key, body_hash, signature, cache)
          else
            {:error, reason} -> {:error, :permerror, reason, result, cache}
          end

        {:error, kind, reason} ->
          {:error, kind, reason, result, cache}
      end
    else
      {:error, reason} -> perm.(reason)
    end
  end

  defp ok_or(nil, reason), do: {:error, reason}
  defp ok_or(value, _reason), do: {:ok, value}

  defp required_tags(tags) do
    if Enum.all?(@required_tags, &Map.has_key?(tags, &1)), do: :ok, else: {:error, :missing_tag}
  end

  defp version(tags) do
    if Tags.strip_whitespace(tags["v"]) == "1", do: :ok, else: {:error, :unsupported_version}
  end

  defp from_signed(headers) do
    if "from" in headers, do: :ok, else: {:error, :from_not_signed}
  end

  defp identity_in_domain(identity, domain) do
    case identity && String.split(identity, "@") |> List.last() do
      nil ->
        {:error, :malformed_signature}

      ^identity ->
        {:error, :malformed_signature}

      i_domain ->
        if Domain.subdomain_of?(i_domain, domain), do: :ok, else: {:error, :domain_mismatch}
    end
  end

  defp numbers(tags, result) do
    bad? = fn tag, parsed -> Map.has_key?(tags, tag) and is_nil(parsed) end

    if bad?.("t", result.signed_at) or bad?.("x", result.expires_at) or
         bad?.("l", result.body_length),
       do: {:error, :malformed_signature},
       else: :ok
  end

  defp times(%{signed_at: t, expires_at: x}, opts) do
    now = now(opts)

    cond do
      x && t && DateTime.compare(x, t) == :lt -> {:error, :invalid_expiry}
      x && DateTime.to_unix(x) < now -> {:error, :expired}
      true -> :ok
    end
  end

  defp now(opts) do
    case Keyword.get(opts, :now) do
      nil -> System.os_time(:second)
      %DateTime{} = dt -> DateTime.to_unix(dt)
      n when is_integer(n) -> n
    end
  end

  defp query_method(tags) do
    case Map.fetch(tags, "q") do
      :error ->
        :ok

      {:ok, q} ->
        if q |> Tags.colon_list() |> Enum.map(&String.downcase/1) |> Enum.member?("dns/txt"),
          do: :ok,
          else: {:error, :unsupported_query_method}
    end
  end

  defp base64(value) do
    case Tags.decode64(value) do
      {:ok, ""} -> {:error, :malformed_signature}
      {:ok, bin} -> {:ok, bin}
      :error -> {:error, :malformed_signature}
    end
  end

  defp sha1_allowed(:rsa_sha1, opts) do
    if Keyword.get(opts, :allow_sha1, false), do: :ok, else: {:error, :weak_algorithm}
  end

  defp sha1_allowed(_, _opts), do: :ok

  defp fetch_key(selector, domain, opts) do
    case DNS.lookup(selector <> "._domainkey." <> domain, :txt, opts) do
      {:ok, records} ->
        case Enum.map(records, &Key.parse/1) do
          [single] ->
            with {:error, reason} <- single, do: {:error, :permerror, reason}

          parsed ->
            case for({:ok, key} <- parsed, do: key) do
              [key] -> {:ok, key}
              [] -> {:error, :permerror, :malformed_key}
              _ -> {:error, :permerror, :multiple_keys}
            end
        end

      {:error, reason} when reason in [:nxdomain, :no_data] ->
        {:error, :permerror, :no_key}

      {:error, :deadline} ->
        {:error, :temperror, :deadline}

      {:error, :temperror} ->
        {:error, :temperror, :dns_error}
    end
  end

  defp key_matches(key, algorithm, result, domain, opts) do
    {key_type, hash} = algorithm_parts(algorithm)

    cond do
      key.type != key_type ->
        {:error, :key_algorithm_mismatch}

      key.hashes != nil and hash not in key.hashes ->
        {:error, :key_hash_mismatch}

      key.services != nil and "email" not in key.services and "*" not in key.services ->
        {:error, :key_service_mismatch}

      "s" in key.flags and identity_domain(result.identity) != domain ->
        {:error, :strict_identity_mismatch}

      key.type == :rsa and key.bits < Keyword.get(opts, :min_key_bits, 1024) ->
        {:error, :key_too_small}

      true ->
        :ok
    end
  end

  defp identity_domain(identity), do: identity |> String.split("@") |> List.last()

  defp algorithm_parts(:rsa_sha256), do: {:rsa, "sha256"}
  defp algorithm_parts(:rsa_sha1), do: {:rsa, "sha1"}
  defp algorithm_parts(:ed25519_sha256), do: {:ed25519, "sha256"}

  defp hash_algorithm(:rsa_sha1), do: :sha
  defp hash_algorithm(_), do: :sha256

  defp verify_crypto(msg, raw_sig, result, {hc, bc}, key, body_hash, signature, cache) do
    hash = hash_algorithm(result.algorithm)
    {canonical_body, cache} = canonical_body(msg, bc, cache)

    case limit_body(canonical_body, result.body_length) do
      :error ->
        {:error, :permerror, :body_length_exceeds, result, cache}

      {:ok, signed_body} ->
        if same_hash?(:crypto.hash(hash, signed_body), body_hash) do
          data = header_data(msg, result.signed_headers, raw_sig, hc)

          if crypto_verify(result.algorithm, key.key, data, signature) do
            {:ok, %{result | result: :pass, warnings: warnings(msg, result)}, cache}
          else
            {:error, :fail, :signature_mismatch, result, cache}
          end
        else
          {:error, :fail, :body_hash_mismatch, result, cache}
        end
    end
  end

  defp same_hash?(a, b), do: byte_size(a) == byte_size(b) and :crypto.hash_equals(a, b)

  defp canonical_body(msg, algorithm, cache) do
    case Map.fetch(cache, algorithm) do
      {:ok, body} ->
        {body, cache}

      :error ->
        body = Canonical.body(msg.body, algorithm)
        {body, Map.put(cache, algorithm, body)}
    end
  end

  defp limit_body(body, nil), do: {:ok, body}
  defp limit_body(body, l) when l <= byte_size(body), do: {:ok, binary_part(body, 0, l)}
  defp limit_body(_body, _l), do: :error

  defp header_data(msg, signed_headers, raw_sig, hc) do
    picked = pick_headers(msg.headers, signed_headers)
    sig = raw_sig |> remove_b_value() |> Canonical.header(hc) |> String.trim_trailing("\r\n")
    IO.iodata_to_binary([Enum.map(picked, &Canonical.header(&1, hc)), sig])
  end

  # For each name, take the header fields from the bottom up (RFC 6376
  # 5.4.2). A name listed more often than it appears adds nothing.
  defp pick_headers(headers, names) do
    pools =
      headers
      |> Enum.reverse()
      |> Enum.group_by(fn {name, _} -> name end, fn {_, raw} -> raw end)

    {picked, _} =
      Enum.flat_map_reduce(names, pools, fn name, pools ->
        name = String.downcase(name)

        case Map.get(pools, name, []) do
          [raw | rest] -> {[raw], Map.put(pools, name, rest)}
          [] -> {[], pools}
        end
      end)

    picked
  end

  # Empties the value of the b= tag, keeping everything else as it is.
  defp remove_b_value(raw) do
    [name, value] = :binary.split(raw, ":")

    value =
      value
      |> :binary.split(";", [:global])
      |> Enum.map(fn segment ->
        case :binary.split(segment, "=") do
          [tag, _value] -> if Tags.trim(tag) == "b", do: tag <> "=", else: segment
          _ -> segment
        end
      end)
      |> Enum.join(";")

    name <> ":" <> value
  end

  defp crypto_verify(algorithm, key, data, signature) do
    case algorithm do
      :ed25519_sha256 ->
        :crypto.verify(:eddsa, :none, :crypto.hash(:sha256, data), signature, [key, :ed25519])

      _ ->
        :public_key.verify(data, hash_algorithm(algorithm), signature, key)
    end
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp warnings(msg, result) do
    signed = result.signed_headers
    count = fn list, name -> Enum.count(list, &(&1 == name)) end
    from_headers = msg.headers |> Enum.map(&elem(&1, 0)) |> count.("from")

    [
      count.(signed, "from") <= from_headers && :from_not_oversigned,
      result.body_length != nil && :body_length_limit,
      "subject" not in signed && :subject_not_signed,
      "to" not in signed && :to_not_signed,
      result.algorithm == :rsa_sha1 && :weak_algorithm
    ]
    |> Enum.filter(& &1)
  end

  @doc """
  Signs `raw` and returns it with the new `DKIM-Signature` header on top.

  Pass a list of signer options to add several signatures at once, such as an
  RSA and an Ed25519 one. The first in the list ends up on top.
  """
  @spec sign(binary(), keyword() | [keyword()]) :: {:ok, binary()} | {:error, atom()}
  def sign(raw, signer_opts) when is_binary(raw) do
    signers = if Keyword.keyword?(signer_opts), do: [signer_opts], else: signer_opts
    newline = if :binary.match(raw, "\r\n") == :nomatch and raw != "", do: "\n", else: "\r\n"

    signers
    |> Enum.reduce_while([], fn opts, acc ->
      case signature_header(raw, opts) do
        {:ok, header} -> {:cont, [String.replace(header, "\r\n", newline) <> newline | acc]}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:error, _} = error -> error
      headers -> {:ok, IO.iodata_to_binary([Enum.reverse(headers), raw])}
    end
  end

  @doc """
  Returns the `DKIM-Signature` header for `raw`, without a final line break.
  """
  @spec signature_header(binary(), keyword()) :: {:ok, String.t()} | {:error, atom()}
  def signature_header(raw, opts) when is_binary(raw) do
    with {:ok, domain} <- required(opts, :domain, :missing_domain),
         {:ok, domain} <- ascii_domain(domain),
         {:ok, selector} <- required(opts, :selector, :missing_selector),
         {:ok, key_opt} <- required(opts, :private_key, :missing_private_key),
         {:ok, {key_type, _} = key} <- Key.private_key(key_opt),
         {:ok, algorithm} <- sign_algorithm(Keyword.get(opts, :algorithm), key_type),
         {:ok, {hc, bc}} <- sign_canonicalization(Keyword.get(opts, :canonicalization)),
         {:ok, header_names} <- sign_headers(opts),
         {:ok, msg} <- Message.parse(raw) do
      body = Canonical.body(msg.body, bc)
      now = now(opts)
      names = expand_headers(msg, header_names, Keyword.get(opts, :oversign, @default_oversign))

      tags =
        [
          {"v", "1"},
          {"a", algorithm_name(algorithm)},
          {"c", "#{hc}/#{bc}"},
          {"d", domain},
          {"s", selector},
          opts[:identity] && {"i", opts[:identity]},
          {"t", Integer.to_string(now)},
          opts[:expires_in] && {"x", Integer.to_string(now + opts[:expires_in])},
          opts[:body_length] && {"l", Integer.to_string(byte_size(body))},
          {"h", names},
          {"bh", Base.encode64(:crypto.hash(:sha256, body))}
        ]
        |> Enum.filter(& &1)

      unsigned = format_tags(tags) <> "\r\n b="
      picked = pick_headers(msg.headers, Enum.map(names, &String.downcase/1))

      data =
        IO.iodata_to_binary([
          Enum.map(picked, &Canonical.header(&1, hc)),
          unsigned |> Kernel.<>("\r\n") |> Canonical.header(hc) |> String.trim_trailing("\r\n")
        ])

      {:ok, unsigned <> fold_signature(sign_data(key, data))}
    end
  end

  defp required(opts, key, reason) do
    case Keyword.get(opts, key) do
      nil -> {:error, reason}
      "" -> {:error, reason}
      value -> {:ok, value}
    end
  end

  defp ascii_domain(domain) do
    case Domain.to_ascii(domain) do
      {:ok, ascii} -> {:ok, ascii}
      {:error, _} -> {:error, :invalid_domain}
    end
  end

  defp sign_algorithm(nil, :rsa), do: {:ok, :rsa_sha256}
  defp sign_algorithm(nil, :ed25519), do: {:ok, :ed25519_sha256}
  defp sign_algorithm(:rsa_sha256, :rsa), do: {:ok, :rsa_sha256}
  defp sign_algorithm(:ed25519_sha256, :ed25519), do: {:ok, :ed25519_sha256}

  defp sign_algorithm(a, _) when a in [:rsa_sha256, :ed25519_sha256],
    do: {:error, :key_algorithm_mismatch}

  defp sign_algorithm(_, _), do: {:error, :unsupported_algorithm}

  defp sign_canonicalization(nil), do: {:ok, {:relaxed, :relaxed}}

  defp sign_canonicalization({h, b} = c)
       when h in [:simple, :relaxed] and b in [:simple, :relaxed],
       do: {:ok, c}

  defp sign_canonicalization(_), do: {:error, :unsupported_canonicalization}

  defp sign_headers(opts) do
    names = Keyword.get(opts, :headers, @default_headers)

    if Enum.any?(names, &(String.downcase(&1) == "from")),
      do: {:ok, names},
      else: {:error, :from_not_signed}
  end

  defp expand_headers(msg, names, oversign) do
    oversign = MapSet.new(oversign, &String.downcase/1)
    present = msg.headers |> Enum.map(&elem(&1, 0)) |> Enum.frequencies()

    names
    |> Enum.uniq_by(&String.downcase/1)
    |> Enum.flat_map(fn name ->
      lname = String.downcase(name)
      extra = if MapSet.member?(oversign, lname), do: 1, else: 0
      List.duplicate(name, Map.get(present, lname, 0) + extra)
    end)
  end

  defp algorithm_name(:rsa_sha256), do: "rsa-sha256"
  defp algorithm_name(:ed25519_sha256), do: "ed25519-sha256"

  defp sign_data({:rsa, key}, data), do: :public_key.sign(data, :sha256, key)

  defp sign_data({:ed25519, seed}, data),
    do: :crypto.sign(:eddsa, :none, :crypto.hash(:sha256, data), [seed, :ed25519])

  # Lays the tags out in lines of at most 78 characters. The h= list folds
  # at its colons, which RFC 6376 allows.
  defp format_tags(tags) do
    pieces =
      Enum.flat_map(tags, fn
        {"h", names} ->
          last = length(names) - 1

          names
          |> Enum.with_index()
          |> Enum.map(fn {name, i} ->
            text = if(i == 0, do: "h=", else: "") <> name <> if(i == last, do: ";", else: ":")
            {text, if(i == 0, do: " ", else: "")}
          end)

        {tag, value} ->
          [{tag <> "=" <> value <> ";", " "}]
      end)

    {lines, current} =
      Enum.reduce(pieces, {[], "DKIM-Signature:"}, fn {text, glue}, {lines, current} ->
        if byte_size(current) + byte_size(glue) + byte_size(text) > 78 do
          {[current | lines], " " <> text}
        else
          {lines, current <> glue <> text}
        end
      end)

    [current | lines] |> Enum.reverse() |> Enum.join("\r\n")
  end

  defp fold_signature(signature) do
    b64 = Base.encode64(signature)
    {first, rest} = String.split_at(b64, 75)

    [first | chunk(rest, 76)] |> Enum.join("\r\n ")
  end

  defp chunk("", _size), do: []

  defp chunk(s, size) do
    {head, tail} = String.split_at(s, size)
    [head | chunk(tail, size)]
  end

  @doc """
  Generates a DKIM key: RSA (2048 bits by default) or Ed25519.

  Returns the private key as PEM and the TXT record to publish. With
  `:selector` and `:domain` given, also returns the name to publish it at,
  `<selector>._domainkey.<domain>`.

  Options: `:bits` (RSA only), `:selector`, `:domain`.
  """
  @spec generate_key(:rsa | :ed25519, keyword()) :: %{
          required(:private_key) => String.t(),
          required(:dns_record) => String.t(),
          optional(:dns_name) => String.t()
        }
  def generate_key(type \\ :rsa, opts \\ []) when type in [:rsa, :ed25519] do
    key = Key.generate(type, opts)

    case {opts[:selector], opts[:domain]} do
      {s, d} when is_binary(s) and is_binary(d) ->
        Map.put(key, :dns_name, "#{s}._domainkey.#{Domain.to_ascii!(d)}")

      _ ->
        key
    end
  end
end
