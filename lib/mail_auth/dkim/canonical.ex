defmodule MailAuth.DKIM.Canonical do
  @moduledoc false

  # DKIM canonicalization, RFC 6376 section 3.4. The input is already in
  # CRLF form (see MailAuth.Message).

  @type algorithm :: :simple | :relaxed

  @doc "Canonicalizes one raw header field, including its final CRLF."
  @spec header(binary(), algorithm()) :: binary()
  def header(raw, :simple), do: raw

  def header(raw, :relaxed) do
    case :binary.split(raw, ":") do
      [name, value] ->
        relaxed_name(name) <> ":" <> relaxed_value(value) <> "\r\n"

      [name] ->
        relaxed_name(name) <> ":\r\n"
    end
  end

  defp relaxed_name(name), do: name |> MailAuth.Tags.trim() |> String.downcase()

  defp relaxed_value(value) do
    value
    |> :binary.split([" ", "\t", "\r", "\n"], [:global, :trim_all])
    |> Enum.join(" ")
  end

  @doc "Canonicalizes a body."
  @spec body(binary(), algorithm()) :: binary()
  def body(body, :simple) do
    case trim_trailing_crlf(body) do
      "" -> "\r\n"
      trimmed -> trimmed <> "\r\n"
    end
  end

  def body(body, :relaxed) do
    body
    |> :binary.split("\r\n", [:global])
    |> Enum.map(&relaxed_line/1)
    |> drop_trailing_empty()
    |> case do
      [] -> ""
      lines -> IO.iodata_to_binary([Enum.intersperse(lines, "\r\n"), "\r\n"])
    end
  end

  defp relaxed_line(line) do
    if :binary.match(line, [" ", "\t"]) == :nomatch do
      line
    else
      # Runs of WSP become one space; WSP at the end of a line goes.
      collapse_wsp(line, <<>>, false)
    end
  end

  defp collapse_wsp(<<c, rest::binary>>, acc, _wsp) when c in [?\s, ?\t],
    do: collapse_wsp(rest, acc, true)

  defp collapse_wsp(<<c, rest::binary>>, acc, true),
    do: collapse_wsp(rest, <<acc::binary, ?\s, c>>, false)

  defp collapse_wsp(<<c, rest::binary>>, acc, false),
    do: collapse_wsp(rest, <<acc::binary, c>>, false)

  defp collapse_wsp(<<>>, acc, _wsp), do: acc

  defp drop_trailing_empty(lines) do
    lines |> Enum.reverse() |> Enum.drop_while(&(&1 == "")) |> Enum.reverse()
  end

  defp trim_trailing_crlf(body) do
    size = byte_size(body)

    if size >= 2 and binary_part(body, size - 2, 2) == "\r\n",
      do: trim_trailing_crlf(binary_part(body, 0, size - 2)),
      else: body
  end
end
