defmodule MailAuth.Tags do
  @moduledoc false

  # Tag lists, as in RFC 6376 section 3.2: `name=value; name=value`. Used for
  # DKIM signatures, DKIM key records and DMARC records.

  @doc """
  Parses a tag list into `{name, value}` pairs, in order. Names keep their case.
  Values have surrounding whitespace, folding included, removed.
  """
  @spec parse(binary()) :: {:ok, [{String.t(), String.t()}]} | {:error, :malformed | :duplicate}
  def parse(s) when is_binary(s) do
    s
    |> :binary.split(";", [:global])
    |> Enum.reduce_while({[], MapSet.new()}, fn segment, {acc, seen} ->
      case parse_segment(segment) do
        :empty ->
          {:cont, {acc, seen}}

        {:ok, name, value} ->
          if MapSet.member?(seen, name),
            do: {:halt, {:error, :duplicate}},
            else: {:cont, {[{name, value} | acc], MapSet.put(seen, name)}}

        :error ->
          {:halt, {:error, :malformed}}
      end
    end)
    |> case do
      {:error, _} = error -> error
      {acc, _} -> {:ok, Enum.reverse(acc)}
    end
  end

  defp parse_segment(segment) do
    case :binary.split(segment, "=") do
      [name, value] ->
        name = trim(name)

        if Regex.match?(~r/\A[A-Za-z][A-Za-z0-9_]*\z/, name),
          do: {:ok, name, trim(value)},
          else: :error

      [other] ->
        if trim(other) == "", do: :empty, else: :error
    end
  end

  @doc "Trims spaces, tabs, CR and LF from both ends."
  @spec trim(binary()) :: binary()
  def trim(s), do: s |> trim_leading() |> trim_trailing()

  defp trim_leading(<<c, rest::binary>>) when c in [?\s, ?\t, ?\r, ?\n], do: trim_leading(rest)
  defp trim_leading(s), do: s

  defp trim_trailing(""), do: ""

  defp trim_trailing(s) do
    case :binary.last(s) do
      c when c in [?\s, ?\t, ?\r, ?\n] -> trim_trailing(binary_part(s, 0, byte_size(s) - 1))
      _ -> s
    end
  end

  @doc "Removes all whitespace, as allowed inside base64 values and tag lists."
  @spec strip_whitespace(binary()) :: binary()
  def strip_whitespace(s), do: for(<<c <- s>>, c not in [?\s, ?\t, ?\r, ?\n], into: "", do: <<c>>)

  @doc "Splits a colon-separated list, as in `h=` or `s=`, trimming each item."
  @spec colon_list(binary()) :: [String.t()]
  def colon_list(s), do: s |> :binary.split(":", [:global]) |> Enum.map(&strip_whitespace/1)

  @doc "Decodes base64 with whitespace removed. Padding is optional."
  @spec decode64(binary()) :: {:ok, binary()} | :error
  def decode64(s) do
    s = strip_whitespace(s)

    case Base.decode64(s) do
      {:ok, _} = ok -> ok
      :error -> Base.decode64(s, padding: false)
    end
  end
end
