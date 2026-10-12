defmodule MailAuth.DKIM.Canonical do
  @moduledoc false

  # DKIM canonicalization, RFC 6376 section 3.4.
  #
  # Header fields come from MailAuth.Message in CRLF form. The body is read
  # as stored: a bare LF ends a line just as CRLF does. The body is hashed in
  # one pass, without building the canonical body, so a large body costs no
  # memory beyond the input.

  @type algorithm :: :simple | :relaxed

  # Bytes collected before they go to the hash.
  @chunk 65_536
  # CRLFs written at once for a run of empty lines.
  @crlfs_per_write 4096
  @crlfs :binary.copy("\r\n", @crlfs_per_write)

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

  @doc """
  Hashes the canonical body, or its first `limit` bytes when `limit` is not
  `nil`. Returns the hash and the number of bytes hashed, or
  `{:error, :body_length_exceeds}` when the canonical body is shorter than
  `limit`.
  """
  @spec body_hash(binary(), algorithm(), :sha | :sha256, non_neg_integer() | nil) ::
          {:ok, binary(), non_neg_integer()} | {:error, :body_length_exceeds}
  def body_hash(body, algorithm, hash, limit) do
    out = {:crypto.hash_init(hash), &:crypto.hash_update/2, 0, limit}

    case run(body, algorithm, out) do
      {:ok, ctx, length} -> {:ok, :crypto.hash_final(ctx), length}
      :error -> {:error, :body_length_exceeds}
    end
  end

  @doc "Returns the canonical body. Only for tests; DKIM uses `body_hash/4`."
  @spec body(binary(), algorithm()) :: binary()
  def body(body, algorithm) do
    {:ok, acc, _} = run(body, algorithm, {[], &[&1 | &2], 0, nil})
    IO.iodata_to_binary(acc)
  end

  # `out` is {sink, update, bytes written, limit}. Reaching the limit throws,
  # so the rest of the body is not read.
  defp run(body, algorithm, out) do
    {buf, out} =
      case algorithm do
        :simple -> simple(body, <<>>, false, 0, out)
        :relaxed -> relaxed(body, <<>>, false, false, 0, out)
      end

    case write(buf, out) do
      {sink, _, written, limit} when limit == nil or written >= limit -> {:ok, sink, written}
      _ -> :error
    end
  catch
    {:limit_reached, sink, limit} -> {:ok, sink, limit}
  end

  # Simple (section 3.4.3): lines unchanged, empty lines at the end dropped,
  # and an empty body is one CRLF. `line?` is true once the current line has
  # a byte; `empty` counts empty lines not yet written.
  defp simple(<<"\r\n", rest::binary>>, buf, line?, empty, out),
    do: simple_eol(rest, buf, line?, empty, out)

  defp simple(<<"\n", rest::binary>>, buf, line?, empty, out),
    do: simple_eol(rest, buf, line?, empty, out)

  defp simple(<<c, rest::binary>>, buf, true, 0, out) when byte_size(buf) < @chunk,
    do: simple(rest, <<buf::binary, c>>, true, 0, out)

  defp simple(<<c, rest::binary>>, buf, _line?, empty, out) do
    {buf, out} = crlfs(buf, empty, out)
    {buf, out} = flush(<<buf::binary, c>>, out)
    simple(rest, buf, true, 0, out)
  end

  defp simple(<<>>, buf, true, _empty, out), do: {<<buf::binary, "\r\n">>, out}

  defp simple(<<>>, buf, false, _empty, {_, _, written, _} = out) do
    if written == 0 and buf == <<>>, do: {"\r\n", out}, else: {buf, out}
  end

  defp simple_eol(rest, buf, true, 0, out) do
    {buf, out} = flush(<<buf::binary, "\r\n">>, out)
    simple(rest, buf, false, 0, out)
  end

  defp simple_eol(rest, buf, false, empty, out), do: simple(rest, buf, false, empty + 1, out)

  # Relaxed (section 3.4.4): runs of WSP become one space, WSP at the end of
  # a line goes, and empty lines at the end are dropped. A line of only WSP
  # is empty. `wsp?` is true after WSP not yet written.
  defp relaxed(<<"\r\n", rest::binary>>, buf, _wsp?, line?, empty, out),
    do: relaxed_eol(rest, buf, line?, empty, out)

  defp relaxed(<<"\n", rest::binary>>, buf, _wsp?, line?, empty, out),
    do: relaxed_eol(rest, buf, line?, empty, out)

  defp relaxed(<<c, rest::binary>>, buf, _wsp?, line?, empty, out) when c in [?\s, ?\t],
    do: relaxed(rest, buf, true, line?, empty, out)

  defp relaxed(<<c, rest::binary>>, buf, false, true, 0, out) when byte_size(buf) < @chunk,
    do: relaxed(rest, <<buf::binary, c>>, false, true, 0, out)

  defp relaxed(<<c, rest::binary>>, buf, wsp?, _line?, empty, out) do
    {buf, out} = crlfs(buf, empty, out)
    buf = if wsp?, do: <<buf::binary, ?\s, c>>, else: <<buf::binary, c>>
    {buf, out} = flush(buf, out)
    relaxed(rest, buf, false, true, 0, out)
  end

  defp relaxed(<<>>, buf, _wsp?, true, _empty, out), do: {<<buf::binary, "\r\n">>, out}
  defp relaxed(<<>>, buf, _wsp?, false, _empty, out), do: {buf, out}

  defp relaxed_eol(rest, buf, true, 0, out) do
    {buf, out} = flush(<<buf::binary, "\r\n">>, out)
    relaxed(rest, buf, false, false, 0, out)
  end

  defp relaxed_eol(rest, buf, false, empty, out),
    do: relaxed(rest, buf, false, false, empty + 1, out)

  # Writes the CRLFs of `n` empty lines, a block at a time.
  defp crlfs(buf, 0, out), do: {buf, out}

  defp crlfs(buf, n, out) do
    count = min(n, @crlfs_per_write)
    {buf, out} = flush(<<buf::binary, binary_part(@crlfs, 0, count * 2)::binary>>, out)
    crlfs(buf, n - count, out)
  end

  defp flush(buf, out) when byte_size(buf) < @chunk, do: {buf, out}
  defp flush(buf, out), do: {<<>>, write(buf, out)}

  defp write(<<>>, out), do: out

  defp write(buf, {sink, update, written, nil}),
    do: {update.(sink, buf), update, written + byte_size(buf), nil}

  defp write(buf, {sink, update, written, limit}) do
    if written + byte_size(buf) >= limit do
      throw({:limit_reached, update.(sink, binary_part(buf, 0, limit - written)), limit})
    else
      {update.(sink, buf), update, written + byte_size(buf), limit}
    end
  end
end
