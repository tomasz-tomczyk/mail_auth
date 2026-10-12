defmodule MailAuth.SPF.Macro do
  @moduledoc false

  # SPF macro strings, RFC 7208 section 7.

  @letters ~c"slodiphcrtv"
  @exp_only ~c"crt"
  @delimiters ~c".-+,/_="

  @type part ::
          {:literal, binary()}
          | {:macro, char(), non_neg_integer() | nil, boolean(), [char()], boolean()}
  @type t :: [part()]

  @doc """
  Parses a macro string. With `exp: true`, the letters c, r and t are allowed
  and spaces are literal, as in explanation text.
  """
  @spec parse(binary(), keyword()) :: {:ok, t()} | :error
  def parse(s, opts \\ []), do: parse(s, Keyword.get(opts, :exp, false), [])

  defp parse(<<>>, _exp, acc), do: {:ok, merge(Enum.reverse(acc))}
  defp parse(<<"%%", rest::binary>>, exp, acc), do: parse(rest, exp, [{:literal, "%"} | acc])
  defp parse(<<"%_", rest::binary>>, exp, acc), do: parse(rest, exp, [{:literal, " "} | acc])
  defp parse(<<"%-", rest::binary>>, exp, acc), do: parse(rest, exp, [{:literal, "%20"} | acc])

  defp parse(<<"%{", rest::binary>>, exp, acc) do
    with [body, rest] <- :binary.split(rest, "}"),
         {:ok, macro} <- macro(body, exp) do
      parse(rest, exp, [macro | acc])
    else
      _ -> :error
    end
  end

  defp parse(<<"%", _::binary>>, _exp, _acc), do: :error

  defp parse(<<c, rest::binary>>, exp, acc) when c in 0x21..0x7E or (exp and c == ?\s),
    do: parse(rest, exp, [{:literal, <<c>>} | acc])

  defp parse(_, _exp, _acc), do: :error

  defp macro(<<letter, rest::binary>>, exp) do
    lower = if letter in ?A..?Z, do: letter + 32, else: letter

    with true <- lower in @letters,
         true <- exp or lower not in @exp_only,
         [_, digits, r, delims] <- Regex.run(~r/\A([0-9]*)([rR]?)([.\-+,\/_=]*)\z/, rest),
         {:ok, digits} <- digits(digits) do
      {:ok, {:macro, lower, digits, r != "", String.to_charlist(delims), letter != lower}}
    else
      _ -> :error
    end
  end

  defp macro(_, _exp), do: :error

  defp digits(""), do: {:ok, nil}

  defp digits(s) do
    case Integer.parse(s) do
      {0, ""} -> :error
      {n, ""} when n <= 128 -> {:ok, n}
      _ -> :error
    end
  end

  defp merge(parts) do
    parts
    |> Enum.chunk_by(&match?({:literal, _}, &1))
    |> Enum.flat_map(fn
      [{:literal, _} | _] = lits -> [{:literal, Enum.map_join(lits, &elem(&1, 1))}]
      macros -> macros
    end)
  end

  @doc "True when the string ends in a macro or in a dot and a top label (RFC 7208 7.1)."
  @spec valid_domain_end?(t()) :: boolean()
  def valid_domain_end?([]), do: false

  def valid_domain_end?(parts) do
    case List.last(parts) do
      {:macro, _, _, _, _, _} ->
        true

      {:literal, lit} ->
        Regex.match?(
          ~r/\.([a-z0-9]*[a-z][a-z0-9]*|[a-z0-9]+-[a-z0-9-]*[a-z0-9])\.?\z/i,
          lit
        )
    end
  end

  @doc "True when the string uses the given letter."
  @spec uses?(t(), char()) :: boolean()
  def uses?(parts, letter), do: Enum.any?(parts, &match?({:macro, ^letter, _, _, _, _}, &1))

  @doc """
  Expands a macro string. `vars` maps each letter to its value; `:p` may be a
  function, called only when the string uses it.
  """
  @spec expand(t(), map()) :: binary()
  def expand(parts, vars) do
    Enum.map_join(parts, fn
      {:literal, lit} ->
        lit

      {:macro, letter, digits, reverse, delims, escape} ->
        value = Map.get(vars, letter, "")
        value = if is_function(value, 0), do: value.(), else: value
        value |> transform(digits, reverse, delims) |> maybe_escape(escape)
    end)
  end

  defp transform(value, nil, false, []), do: value

  defp transform(value, digits, reverse, delims) do
    delims = if delims == [], do: [?.], else: delims
    parts = :binary.split(value, Enum.map(delims, &<<&1>>), [:global])
    parts = if reverse, do: Enum.reverse(parts), else: parts
    parts = if digits, do: Enum.take(parts, -digits), else: parts
    Enum.join(parts, ".")
  end

  defp maybe_escape(value, false), do: value

  defp maybe_escape(value, true) do
    for <<c <- value>>, into: "" do
      if c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c in ~c"-._~",
        do: <<c>>,
        else: "%" <> Base.encode16(<<c>>)
    end
  end

  @doc false
  def delimiters, do: @delimiters
end
