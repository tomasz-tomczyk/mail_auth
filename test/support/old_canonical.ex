defmodule MailAuth.Test.OldCanonical do
  @moduledoc false

  # Message parsing and body canonicalization from mail_auth 0.1.0, copied
  # as a reference for the property tests.

  def normalize(raw) do
    if :binary.match(raw, "\n") == :nomatch,
      do: raw,
      else: Regex.replace(~r/(?<!\r)\n/, raw, "\r\n")
  end

  # A bare LF in the raw header block or in the empty line after it.
  def bare_lf?(raw, body) do
    head = binary_part(raw, 0, byte_size(raw) - byte_size(body))
    Regex.match?(~r/(?<!\r)\n/, head)
  end

  def parse(raw) do
    {header_bytes, body} = split(raw)

    if byte_size(header_bytes) > 1_048_576 do
      {:error, :headers_too_large}
    else
      case fields(header_bytes) do
        {:ok, headers} -> {:ok, %{headers: headers, body: body}}
        :error -> {:error, :headers_too_large}
      end
    end
  end

  defp fields(""), do: {:ok, []}

  defp fields(header_bytes) do
    header_bytes
    |> :binary.split("\r\n", [:global, :trim])
    |> Enum.reduce_while({[], 0}, fn line, {acc, count} ->
      case {line, acc} do
        {<<c, _::binary>>, [{name, raw} | rest]} when c in [?\s, ?\t] ->
          {:cont, {[{name, raw <> line <> "\r\n"} | rest], count}}

        _ when count >= 1000 ->
          {:halt, :error}

        _ ->
          {:cont, {[{field_name(line), line <> "\r\n"} | acc], count + 1}}
      end
    end)
    |> case do
      :error -> :error
      {acc, _} -> {:ok, Enum.reverse(acc)}
    end
  end

  defp field_name(line) do
    case :binary.split(line, ":") do
      [name, _] -> name |> String.trim() |> String.downcase()
      [_] -> line |> String.trim() |> String.downcase()
    end
  end

  defp split(<<"\r\n", body::binary>>), do: {"", body}

  defp split(raw) do
    case :binary.match(raw, "\r\n\r\n") do
      {pos, 4} ->
        {binary_part(raw, 0, pos + 2), binary_part(raw, pos + 4, byte_size(raw) - pos - 4)}

      :nomatch ->
        if String.ends_with?(raw, "\r\n") or raw == "",
          do: {raw, ""},
          else: {raw <> "\r\n", ""}
    end
  end

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
