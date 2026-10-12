defmodule MailAuth.CLI do
  @moduledoc false

  # Shared code for the mix tasks.

  @doc "Starts the library and its dependencies."
  def start do
    Mix.Task.run("app.start", ["--no-start"])
    {:ok, _} = Application.ensure_all_started(:mail_auth)
    :ok
  end

  @doc "Options for every call: the resolver, from --dns-file when given."
  def resolver_opts(parsed) do
    case parsed[:dns_file] do
      nil ->
        []

      path ->
        case MailAuth.Resolver.Static.parse_file(path) do
          {:ok, records} -> [resolver: MailAuth.Resolver.Static, records: records]
          {:error, reason} -> Mix.raise("Could not read #{path}: #{inspect(reason)}")
        end
    end
  end

  def read!(path) do
    case File.read(path) do
      {:ok, contents} -> contents
      {:error, reason} -> Mix.raise("Could not read #{path}: #{:file.format_error(reason)}")
    end
  end

  @doc "Turns results into plain maps and lists, for JSON."
  def plain(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  def plain(%_{} = struct), do: struct |> Map.from_struct() |> plain()

  def plain(map) when is_map(map), do: Map.new(map, fn {k, v} -> {to_string(k), plain(v)} end)
  def plain(list) when is_list(list), do: Enum.map(list, &plain/1)
  def plain({a, b}) when is_atom(a) and is_atom(b), do: [plain(a), plain(b)]
  def plain({domain, record}) when is_binary(domain) and is_binary(record), do: [domain, record]
  def plain(tuple) when is_tuple(tuple), do: tuple |> Tuple.to_list() |> plain()
  def plain(atom) when is_atom(atom) and atom not in [nil, true, false], do: Atom.to_string(atom)
  def plain(other), do: other

  def json(term), do: term |> plain() |> JSON.encode!()

  def list(nil), do: "-"
  def list([]), do: "-"
  def list(items), do: Enum.map_join(items, ", ", &to_string/1)
end
