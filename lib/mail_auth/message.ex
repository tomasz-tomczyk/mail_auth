defmodule MailAuth.Message do
  @moduledoc false

  # Splits a raw message into header fields and a body.
  #
  # Each header field is kept exactly as it appears, with its folding and the
  # final CRLF, so DKIM can canonicalize it. Bare LF line endings are read as
  # CRLF. Nothing else in the bytes is changed.

  @max_headers 1000
  @max_header_bytes 1_048_576

  defstruct headers: [], body: ""

  @type header :: {name :: String.t(), raw :: binary()}
  @type t :: %__MODULE__{headers: [header()], body: binary()}

  @doc """
  Parses a raw message. Header names are lowercased in the first element of
  each tuple; the second element is the whole field, unchanged.
  """
  @spec parse(binary()) :: {:ok, t()} | {:error, :headers_too_large}
  def parse(raw) when is_binary(raw) do
    raw = normalize_line_endings(raw)
    {header_bytes, body} = split(raw)

    if byte_size(header_bytes) > @max_header_bytes do
      {:error, :headers_too_large}
    else
      case fields(header_bytes) do
        {:ok, headers} -> {:ok, %__MODULE__{headers: headers, body: body}}
        :error -> {:error, :headers_too_large}
      end
    end
  end

  @doc "Turns every LF that has no CR before it into CRLF."
  @spec normalize_line_endings(binary()) :: binary()
  def normalize_line_endings(raw) do
    if :binary.match(raw, "\n") == :nomatch,
      do: raw,
      else: Regex.replace(~r/(?<!\r)\n/, raw, "\r\n")
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

  defp fields(""), do: {:ok, []}

  defp fields(header_bytes) do
    lines = :binary.split(header_bytes, "\r\n", [:global, :trim])

    lines
    |> Enum.reduce_while({[], 0}, fn line, {acc, count} ->
      case {line, acc} do
        {<<c, _::binary>>, [{name, raw} | rest]} when c in [?\s, ?\t] ->
          {:cont, {[{name, raw <> line <> "\r\n"} | rest], count}}

        _ when count >= @max_headers ->
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

  @doc "Returns the value of a raw header field: everything after the first colon."
  @spec value(binary()) :: binary()
  def value(raw) do
    case :binary.split(raw, ":") do
      [_, value] -> value
      [_] -> ""
    end
  end

  @doc "Returns the value with folding removed and outer whitespace trimmed."
  @spec unfolded_value(binary()) :: String.t()
  def unfolded_value(raw) do
    raw |> value() |> String.replace(~r/\r\n(?=[ \t])/, "") |> String.trim()
  end

  @doc "Returns all header fields with the given lowercased name, top to bottom."
  @spec get_all(t(), String.t()) :: [binary()]
  def get_all(%__MODULE__{headers: headers}, name) do
    for {^name, raw} <- headers, do: raw
  end
end
