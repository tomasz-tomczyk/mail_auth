defmodule MailAuth.Message do
  @moduledoc false

  # Splits a raw message into header fields and a body.
  #
  # Each header field is kept exactly as it appears, with its folding and the
  # final CRLF, so DKIM can canonicalize it. Bare LF line endings in the
  # header block are read as CRLF. The body is kept as stored, bare LFs and
  # all; DKIM canonicalization reads a bare LF there as CRLF too. Nothing
  # else in the bytes is changed.

  @max_headers 1000
  @max_header_bytes 1_048_576

  defstruct headers: [], body: "", bare_lf: false

  @type header :: {name :: String.t(), raw :: binary()}
  @type t :: %__MODULE__{headers: [header()], body: binary(), bare_lf: boolean()}

  @doc """
  Parses a raw message. Header names are lowercased in the first element of
  each tuple; the second element is the whole field, unchanged.

  `bare_lf` is true when a line in the header block, or the empty line after
  it, ends in LF without CR.
  """
  @spec parse(binary()) :: {:ok, t()} | {:error, :headers_too_large}
  def parse(raw) when is_binary(raw) do
    with {:ok, header_bytes, body, bare_lf} <- split(raw, 0, false),
         true <- byte_size(header_bytes) <= @max_header_bytes,
         {:ok, headers} <- fields(header_bytes) do
      {:ok, %__MODULE__{headers: headers, body: body, bare_lf: bare_lf}}
    else
      _ -> {:error, :headers_too_large}
    end
  end

  @doc "Turns every LF that has no CR before it into CRLF."
  @spec normalize_line_endings(binary()) :: binary()
  def normalize_line_endings(raw) do
    if :binary.match(raw, "\n") == :nomatch,
      do: raw,
      else: normalize(raw, <<>>)
  end

  defp normalize(<<"\r\n", rest::binary>>, acc), do: normalize(rest, <<acc::binary, "\r\n">>)
  defp normalize(<<"\n", rest::binary>>, acc), do: normalize(rest, <<acc::binary, "\r\n">>)
  defp normalize(<<c, rest::binary>>, acc), do: normalize(rest, <<acc::binary, c>>)
  defp normalize(<<>>, acc), do: acc

  # Finds the first empty line, reading one line at a time from `pos`, and
  # stops once the header block is too large. `bare_lf` is true after a line
  # that ends in LF without CR.
  defp split(raw, pos, bare_lf) do
    case :binary.match(raw, "\n", scope: {pos, byte_size(raw) - pos}) do
      :nomatch ->
        if byte_size(raw) > @max_header_bytes,
          do: :error,
          else: {:ok, whole_header(raw), "", bare_lf}

      {lf, 1} ->
        cr? = lf > pos and :binary.at(raw, lf - 1) == ?\r
        bare_lf = bare_lf or not cr?

        cond do
          lf == pos or (lf == pos + 1 and cr?) ->
            header = normalize_line_endings(binary_part(raw, 0, pos))
            {:ok, header, binary_part(raw, lf + 1, byte_size(raw) - lf - 1), bare_lf}

          lf + 1 > @max_header_bytes ->
            :error

          true ->
            split(raw, lf + 1, bare_lf)
        end
    end
  end

  # Without an empty line, the whole message is the header block, and it
  # ends in CRLF.
  defp whole_header(raw) do
    header = normalize_line_endings(raw)

    if String.ends_with?(header, "\r\n") or header == "",
      do: header,
      else: header <> "\r\n"
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
