defmodule MailAuth.Address do
  @moduledoc false

  # Reads the addresses of an address list header such as From: (RFC 5322
  # section 3.4): display names, quoted strings, comments, angle brackets and
  # groups. Only the addr-spec of each address is returned.

  @doc "Returns the addr-specs in a header value, in order."
  @spec list(binary()) :: [String.t()]
  def list(value) do
    value
    |> String.replace(~r/\r\n(?=[ \t])/, "")
    |> strip_comments()
    |> split_top_level()
    |> Enum.flat_map(&address/1)
  end

  @doc "Returns the domain of an addr-spec, or nil."
  @spec domain(String.t()) :: String.t() | nil
  def domain(addr) do
    case String.split(addr, "@") do
      [_] ->
        nil

      parts ->
        domain = parts |> List.last() |> String.trim()
        if domain == "", do: nil, else: domain
    end
  end

  # Removes comments, keeping quoted strings. Comments nest.
  defp strip_comments(s), do: strip_comments(s, 0, false, [])

  defp strip_comments(<<?\\, c, rest::binary>>, depth, quoted, acc) do
    acc = if depth == 0, do: [<<?\\, c>> | acc], else: acc
    strip_comments(rest, depth, quoted, acc)
  end

  defp strip_comments(<<?", rest::binary>>, 0, quoted, acc),
    do: strip_comments(rest, 0, not quoted, [?" | acc])

  defp strip_comments(<<?(, rest::binary>>, depth, false, acc),
    do: strip_comments(rest, depth + 1, false, if(depth == 0, do: [?\s | acc], else: acc))

  defp strip_comments(<<?), rest::binary>>, depth, false, acc) when depth > 0,
    do: strip_comments(rest, depth - 1, false, acc)

  defp strip_comments(<<c, rest::binary>>, 0, quoted, acc),
    do: strip_comments(rest, 0, quoted, [c | acc])

  defp strip_comments(<<_c, rest::binary>>, depth, quoted, acc),
    do: strip_comments(rest, depth, quoted, acc)

  defp strip_comments(<<>>, _depth, _quoted, acc),
    do: acc |> Enum.reverse() |> IO.iodata_to_binary()

  # Splits on commas, colons (group start) and semicolons (group end) that are
  # outside quotes and angle brackets. A colon starts a group only outside
  # angle brackets; what came before it is the group's name.
  defp split_top_level(s), do: split_top_level(s, false, false, [], [])

  defp split_top_level(<<?\\, c, rest::binary>>, q, a, cur, acc),
    do: split_top_level(rest, q, a, [c, ?\\ | cur], acc)

  defp split_top_level(<<?", rest::binary>>, q, a, cur, acc),
    do: split_top_level(rest, not q, a, [?" | cur], acc)

  defp split_top_level(<<?<, rest::binary>>, false, _a, cur, acc),
    do: split_top_level(rest, false, true, [?< | cur], acc)

  defp split_top_level(<<?>, rest::binary>>, false, _a, cur, acc),
    do: split_top_level(rest, false, false, [?> | cur], acc)

  defp split_top_level(<<c, rest::binary>>, false, false, _cur, acc) when c == ?:,
    do: split_top_level(rest, false, false, [], acc)

  defp split_top_level(<<c, rest::binary>>, false, false, cur, acc) when c in [?,, ?;],
    do: split_top_level(rest, false, false, [], [finish(cur) | acc])

  defp split_top_level(<<c, rest::binary>>, q, a, cur, acc),
    do: split_top_level(rest, q, a, [c | cur], acc)

  defp split_top_level(<<>>, _q, _a, cur, acc), do: Enum.reverse([finish(cur) | acc])

  defp finish(cur), do: cur |> Enum.reverse() |> IO.iodata_to_binary() |> String.trim()

  defp address(""), do: []

  defp address(part) do
    case Regex.run(~r/<([^<>]*)>\s*\z/, part) do
      [_, inner] -> non_empty(inner |> strip_route() |> unquote_local())
      nil -> non_empty(unquote_local(part))
    end
  end

  # Obsolete source routes: <@a.example,@b.example:user@c.example>
  defp strip_route(inner) do
    case String.split(inner, ":") do
      [_route, addr] -> addr
      _ -> inner
    end
  end

  defp unquote_local(addr), do: addr |> String.replace(~r/\s+/, "") |> String.trim()

  defp non_empty(""), do: []
  defp non_empty(addr), do: [addr]
end
