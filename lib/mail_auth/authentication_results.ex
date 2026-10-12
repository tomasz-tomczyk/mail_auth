defmodule MailAuth.AuthenticationResults do
  @moduledoc """
  Writes and reads `Authentication-Results:` headers (RFC 8601).

  ## Trust

  Anyone can write an `Authentication-Results:` header. RFC 8601 says to read
  one only when it comes from a server you were told to trust, and to remove
  the ones claiming to be from your own servers when mail arrives. `parse/2`
  marks each header `trusted?` only when its `authserv_id` is in the
  `:trusted` list, and never trusts a header without one (as Outlook writes
  them).

  Checking DKIM and DMARC yourself, with `MailAuth.authenticate/2`, needs no
  trust in any header.
  """

  alias MailAuth.Message
  alias MailAuth.AuthenticationResults.Method

  @type t :: %__MODULE__{
          authserv_id: String.t() | nil,
          version: String.t() | nil,
          trusted?: boolean(),
          results: [Method.t()],
          warnings: [atom()]
        }

  defstruct authserv_id: nil, version: nil, trusted?: false, results: [], warnings: []

  @doc """
  Writes the `Authentication-Results:` header for a `MailAuth.Result`, under
  `authserv_id`, the name of your server. Returns the whole header field,
  folded, without a final line break.

      iex> result = %MailAuth.Result{dkim: [], spf: %MailAuth.SPF.Result{result: :none, reason: :no_client_ip}}
      iex> MailAuth.AuthenticationResults.format(result, "mx.example.com")
      "Authentication-Results: mx.example.com; none"
  """
  @spec format(MailAuth.Result.t(), String.t()) :: String.t()
  def format(%MailAuth.Result{} = result, authserv_id) do
    methods =
      Enum.map(result.dkim, &dkim/1) ++
        spf(result.spf) ++
        dmarc(result.dmarc)

    case methods do
      [] ->
        "Authentication-Results: #{value(authserv_id)}; none"

      _ ->
        "Authentication-Results: #{value(authserv_id)};\r\n " <>
          Enum.map_join(methods, ";\r\n ", &format_method/1)
    end
  end

  defp dkim(r) do
    {"dkim", r.result, r.reason, nil,
     [
       {"header.d", r.domain},
       {"header.i", r.identity},
       {"header.s", r.selector},
       {"header.a", algorithm(r.algorithm)}
     ]}
  end

  defp algorithm(:rsa_sha256), do: "rsa-sha256"
  defp algorithm(:rsa_sha1), do: "rsa-sha1"
  defp algorithm(:ed25519_sha256), do: "ed25519-sha256"
  defp algorithm(nil), do: nil

  defp spf(nil), do: []
  defp spf(%{reason: :no_client_ip}), do: []

  defp spf(r) do
    prop =
      if r.identity == :helo,
        do: {"smtp.helo", r.helo},
        else: {"smtp.mailfrom", r.mail_from}

    [{"spf", r.result, r.reason, r.ip && "#{r.ip}", [prop]}]
  end

  defp dmarc(nil), do: []

  defp dmarc(r) do
    comment =
      if r.policy,
        do: "p=#{r.policy} dis=#{r.disposition}",
        else: nil

    [
      {"dmarc", r.result, r.reason, comment,
       [{"header.from", r.from_domain}, {"policy.dmarc", r.policy && "#{r.policy}"}]}
    ]
  end

  defp format_method({method, result, reason, comment, props}) do
    [
      "#{method}=#{result}",
      comment && "(#{String.replace(comment, ["(", ")", "\\"], "")})",
      reason && "reason=#{value(Atom.to_string(reason))}"
      | for({k, v} <- props, is_binary(v) and v != "", do: "#{k}=#{pvalue(v)}")
    ]
    |> Enum.filter(& &1)
    |> Enum.join(" ")
  end

  # value = token / quoted-string (RFC 2045)
  defp value(s) do
    if Regex.match?(~r/\A[!#$%&'*+\-.0-9A-Z^_`a-z{|}~]+\z/, s), do: s, else: quoted(s)
  end

  # pvalue = value / [[local-part] "@"] domain-name
  defp pvalue(s) do
    if Regex.match?(~r/\A[!#$%&'*+\-.\/0-9A-Z^_`a-z{|}~@]+\z/, s), do: s, else: quoted(s)
  end

  defp quoted(s), do: "\"" <> String.replace(s, ["\\", "\""], &("\\" <> &1)) <> "\""

  @doc """
  Reads every `Authentication-Results:` header in a message, or one header
  (with or without its name).

  Options:

    * `:trusted`: the `authserv_id`s to trust, such as `["mx.google.com"]`.
      Compared without case

  Unknown methods are kept. A header that can't be read in part gives what
  could be read and the warning `:malformed`.
  """
  @spec parse(binary(), keyword()) :: [t()]
  def parse(input, opts \\ []) when is_binary(input) do
    trusted = opts |> Keyword.get(:trusted, []) |> Enum.map(&String.downcase/1)

    input
    |> header_values()
    |> Enum.map(&parse_value(&1, trusted))
  end

  defp header_values(input) do
    cond do
      Regex.match?(~r/\A[^\s:;=]+:/, input) and
          not Regex.match?(~r/\A\s*authentication-results\s*:[^\r\n]*\z/i, String.trim(input)) ->
        case Message.parse(input) do
          {:ok, msg} ->
            msg |> Message.get_all("authentication-results") |> Enum.map(&Message.value/1)

          {:error, _} ->
            []
        end

      true ->
        [Regex.replace(~r/\A\s*authentication-results\s*:/i, input, "")]
    end
  end

  defp parse_value(value, trusted) do
    value = String.replace(value, ~r/\r?\n(?=[ \t])/, "")

    case tokens(value) do
      {:ok, tokens} -> build(tokens, trusted, [])
      {:partial, tokens} -> build(tokens, trusted, [:malformed])
    end
  end

  defp build(tokens, trusted, warnings) do
    [first | rest] = split_on(tokens, :semi)

    {id, version, rest, warnings} =
      if Enum.any?(first, &match?({:eq, _}, &1)) do
        {nil, nil, [first | rest], [:no_authserv_id | warnings]}
      else
        case first do
          [] -> {nil, nil, rest, [:no_authserv_id | warnings]}
          [{_, id, _}] -> {id, nil, rest, warnings}
          [{_, id, _}, {:word, v, _} | _] -> {id, v, rest, warnings}
          [{_, id, _} | _] -> {id, nil, rest, [:malformed | warnings]}
        end
      end

    {methods, warnings} =
      Enum.reduce(rest, {[], warnings}, fn segment, {acc, warnings} ->
        case resinfo(segment) do
          :skip -> {acc, warnings}
          {:ok, method} -> {[method | acc], warnings}
          :error -> {acc, [:malformed | warnings]}
        end
      end)

    %__MODULE__{
      authserv_id: id,
      version: version,
      trusted?: id != nil and String.downcase(id) in trusted,
      results: Enum.reverse(methods),
      warnings: warnings |> Enum.reverse() |> Enum.uniq()
    }
  end

  defp resinfo([]), do: :skip
  defp resinfo([{:word, word, _}]) when word in ["none", "NONE", "None"], do: :skip

  defp resinfo([{:word, method, _}, {:eq, _}, {_, result, _} | rest]) do
    {method, version} =
      case String.split(method, "/", parts: 2) do
        [m, v] -> {m, String.trim(v)}
        [m] -> {m, nil}
      end

    case props(rest, nil, []) do
      {:ok, reason, props} ->
        {:ok,
         %Method{
           method: String.downcase(method),
           version: version,
           result: Method.result_value(result),
           reason: reason,
           properties: props
         }}

      :error ->
        :error
    end
  end

  defp resinfo(_), do: :error

  defp props([], reason, acc), do: {:ok, reason, acc |> Enum.reverse() |> Map.new()}

  defp props([{:word, key, _}, {:eq, _} | rest], reason, acc) do
    {value, rest} = glue(rest)
    key = String.downcase(key)

    if key == "reason",
      do: props(rest, value, acc),
      else: props(rest, reason, [{key, value} | acc])
  end

  defp props(_, _reason, _acc), do: :error

  # A value runs on through "=" signs and text written without space, as in
  # base64 padding: header.b=abc==
  defp glue([{type, v, _} | rest]) when type in [:word, :quoted], do: glue_more(rest, v)
  defp glue(rest), do: {"", rest}

  defp glue_more([{:eq, :tight} | rest], acc), do: glue_more(rest, acc <> "=")
  defp glue_more([{:word, v, :tight} | rest], acc), do: glue_more(rest, acc <> v)
  defp glue_more(rest, acc), do: {acc, rest}

  defp split_on(tokens, sep) do
    Enum.chunk_while(
      tokens,
      [],
      fn
        ^sep, acc -> {:cont, Enum.reverse(acc), []}
        t, acc -> {:cont, [t | acc]}
      end,
      fn acc -> {:cont, Enum.reverse(acc), []} end
    )
  end

  # Tokens: :semi, {:eq, spacing}, {:word, s, spacing} and {:quoted, s,
  # spacing}, where spacing is :tight when no space or comment came before.
  # Comments and whitespace are dropped.
  defp tokens(s), do: tokens(s, [], :spaced, 0)

  defp tokens(_s, acc, _spacing, n) when n > 10_000, do: {:partial, Enum.reverse(acc)}
  defp tokens(<<>>, acc, _spacing, _n), do: {:ok, Enum.reverse(acc)}

  defp tokens(<<c, rest::binary>>, acc, _spacing, n) when c in [?\s, ?\t, ?\r, ?\n],
    do: tokens(rest, acc, :spaced, n + 1)

  defp tokens(<<?;, rest::binary>>, acc, _spacing, n),
    do: tokens(rest, [:semi | acc], :spaced, n + 1)

  defp tokens(<<?=, rest::binary>>, acc, spacing, n),
    do: tokens(rest, [{:eq, spacing} | acc], :tight, n + 1)

  defp tokens(<<?(, rest::binary>>, acc, _spacing, n) do
    case skip_comment(rest, 1) do
      {:ok, rest} -> tokens(rest, acc, :spaced, n + 1)
      :error -> {:partial, Enum.reverse(acc)}
    end
  end

  defp tokens(<<?", rest::binary>>, acc, spacing, n) do
    case quoted_string(rest, []) do
      {:ok, value, rest} -> tokens(rest, [{:quoted, value, spacing} | acc], :tight, n + 1)
      :error -> {:partial, Enum.reverse(acc)}
    end
  end

  defp tokens(<<?), _rest::binary>>, acc, _spacing, _n), do: {:partial, Enum.reverse(acc)}

  defp tokens(s, acc, spacing, n) do
    [word] = Regex.run(~r/\A[^ \t\r\n;=()"]+/, s)
    rest = binary_part(s, byte_size(word), byte_size(s) - byte_size(word))
    tokens(rest, [{:word, word, spacing} | acc], :tight, n + 1)
  end

  defp skip_comment(_s, depth) when depth > 100, do: :error
  defp skip_comment(<<>>, _depth), do: :error
  defp skip_comment(<<?\\, _c, rest::binary>>, depth), do: skip_comment(rest, depth)
  defp skip_comment(<<?(, rest::binary>>, depth), do: skip_comment(rest, depth + 1)
  defp skip_comment(<<?), rest::binary>>, 1), do: {:ok, rest}
  defp skip_comment(<<?), rest::binary>>, depth), do: skip_comment(rest, depth - 1)
  defp skip_comment(<<_c, rest::binary>>, depth), do: skip_comment(rest, depth)

  defp quoted_string(<<>>, _acc), do: :error
  defp quoted_string(<<?\\, c, rest::binary>>, acc), do: quoted_string(rest, [c | acc])

  defp quoted_string(<<?", rest::binary>>, acc),
    do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary(), rest}

  defp quoted_string(<<c, rest::binary>>, acc), do: quoted_string(rest, [c | acc])
end
