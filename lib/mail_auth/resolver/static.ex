defmodule MailAuth.Resolver.Static do
  @moduledoc """
  A resolver that answers from a map, for tests and for checking mail offline.

  The map's keys are names. Each value is a list of `{type, value}` entries, or
  one of `:nxdomain`, `:temperror` or `:timeout` for the whole name:

      records = %{
        "example.com" => [txt: "v=spf1 ip4:192.0.2.0/24 -all", mx: {10, "mx.example.com"}],
        "mx.example.com" => [a: {192, 0, 2, 1}],
        "_dmarc.example.com" => [txt: "v=DMARC1; p=reject"],
        "broken.example" => :temperror
      }

      MailAuth.authenticate(raw, resolver: MailAuth.Resolver.Static, records: records)

  A TXT value can be a list of strings; they are joined, as the strings of one
  TXT record are. An entry can also be `{type, :temperror}` to fail one type.
  A `{:cname, target}` entry is followed when the name has no records of the
  type asked for.

  Names not in the map are `:nxdomain`. A name in the map with no entries of
  the type asked for is `:no_data`. Names are matched without case and without
  a trailing dot.

  Instead of the `:records` option, the map can be set for the current process
  with `put_records/1`. Tasks started from that process see it too.
  """

  @behaviour MailAuth.Resolver

  @key {__MODULE__, :records}

  @doc "Sets the records for the current process."
  @spec put_records(map()) :: :ok
  def put_records(records) when is_map(records) do
    Process.put(@key, normalize_keys(records))
    :ok
  end

  @doc """
  Parses a file of records, one per line: `name TYPE value`.

  TXT values may be written in double quotes, and several quoted strings are
  joined. MX values are `preference exchange`. A, AAAA and PTR values are as
  written. Empty lines and lines starting with `#` are skipped.

      brisbane._domainkey.example.com TXT "v=DKIM1; p=MIGfMA0..."
      example.com MX 10 mx.example.com
      mx.example.com A 192.0.2.1
  """
  @spec parse_file(String.t()) :: {:ok, map()} | {:error, term()}
  def parse_file(path) do
    with {:ok, contents} <- File.read(path), do: parse_lines(contents)
  end

  @doc "Parses records in the format of `parse_file/1` from a string."
  @spec parse_lines(String.t()) :: {:ok, map()} | {:error, {:bad_line, String.t()}}
  def parse_lines(contents) do
    contents
    |> String.split(["\r\n", "\n"])
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == "" or String.starts_with?(&1, "#")))
    |> Enum.reduce_while(%{}, fn line, acc ->
      case parse_line(line) do
        {:ok, name, entry} -> {:cont, Map.update(acc, name, [entry], &(&1 ++ [entry]))}
        :error -> {:halt, {:error, {:bad_line, line}}}
      end
    end)
    |> case do
      {:error, _} = error -> error
      map -> {:ok, map}
    end
  end

  defp parse_line(line) do
    with [name, type, value] <- String.split(line, ~r/\s+/, parts: 3),
         {:ok, entry} <- parse_value(String.downcase(type), String.trim(value)) do
      {:ok, normalize_name(name), entry}
    else
      _ -> :error
    end
  end

  defp parse_value("txt", value) do
    if String.starts_with?(value, "\"") do
      strings = Regex.scan(~r/"((?:[^"\\]|\\.)*)"/, value, capture: :all_but_first)
      {:ok, {:txt, strings |> List.flatten() |> Enum.map(&unescape/1) |> Enum.join()}}
    else
      {:ok, {:txt, value}}
    end
  end

  defp parse_value("mx", value) do
    with [pref, host] <- String.split(value, ~r/\s+/, parts: 2),
         {pref, ""} <- Integer.parse(pref) do
      {:ok, {:mx, {pref, normalize_name(host)}}}
    else
      _ -> :error
    end
  end

  defp parse_value(type, value) when type in ["a", "aaaa"] do
    case :inet.parse_strict_address(String.to_charlist(value)) do
      {:ok, ip} -> {:ok, {if(type == "a", do: :a, else: :aaaa), ip}}
      _ -> :error
    end
  end

  defp parse_value("ptr", value), do: {:ok, {:ptr, normalize_name(value)}}
  defp parse_value(_, _), do: :error

  defp unescape(s), do: Regex.replace(~r/\\(.)/, s, "\\1")

  @impl true
  def lookup(name, type, opts) do
    records =
      case Keyword.fetch(opts, :records) do
        {:ok, records} -> normalize_keys(records)
        :error -> process_records()
      end

    resolve(records, normalize_name(name), type, 8)
  end

  defp resolve(_records, _name, _type, 0), do: {:error, :temperror, 0}

  defp resolve(records, name, type, hops) do
    case Map.get(records, name) do
      nil -> {:error, :nxdomain, 300}
      :nxdomain -> {:error, :nxdomain, 300}
      :temperror -> {:error, :temperror, 0}
      :timeout -> {:error, :temperror, 0}
      entries when is_list(entries) -> answer(records, entries, type, hops)
    end
  end

  defp answer(records, entries, type, hops) do
    values = for {^type, value} <- entries, do: value

    cond do
      :temperror in values ->
        {:error, :temperror, 0}

      values != [] ->
        {:ok, Enum.map(values, &value(type, &1)), 300}

      cname = List.keyfind(entries, :cname, 0) ->
        resolve(records, normalize_name(elem(cname, 1)), type, hops - 1)

      true ->
        {:error, :no_data, 300}
    end
  end

  defp value(:txt, strings) when is_list(strings), do: Enum.join(strings)
  defp value(:mx, {pref, host}), do: {pref, normalize_name(host)}
  defp value(:ptr, host), do: normalize_name(host)
  defp value(_type, value), do: value

  defp process_records do
    [self() | Process.get(:"$callers", [])]
    |> Enum.find_value(%{}, fn pid ->
      case Process.info(pid, :dictionary) do
        {:dictionary, dict} -> List.keyfind(dict, @key, 0) |> then(&(&1 && elem(&1, 1)))
        nil -> nil
      end
    end)
  end

  defp normalize_keys(records) do
    Map.new(records, fn {name, value} -> {normalize_name(name), value} end)
  end

  defp normalize_name(name), do: name |> String.trim_trailing(".") |> String.downcase()
end
