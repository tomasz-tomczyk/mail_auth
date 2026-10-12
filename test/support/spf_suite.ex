defmodule MailAuth.Test.SPFSuite do
  @moduledoc false

  # Turns the zone data of the RFC 7208 test suite into records for
  # MailAuth.Resolver.Static. As the suite asks of its drivers:
  #
  #   * records of type SPF (99) are served as TXT when the name has no TXT
  #   * `TXT: NONE` means the name has no TXT records
  #   * `TIMEOUT` makes every type the name has no records of time out

  @types [:txt, :a, :aaaa, :mx, :ptr]

  @path "test/fixtures/spf/rfc7208-tests.json"

  def suite do
    case :persistent_term.get({__MODULE__, :suite}, nil) do
      nil ->
        suite = @path |> File.read!() |> JSON.decode!()
        :persistent_term.put({__MODULE__, :suite}, suite)
        suite

      suite ->
        suite
    end
  end

  def records(doc_index) do
    zonedata = Enum.at(suite(), doc_index)["zonedata"] || %{}

    Map.new(zonedata, fn {name, entries} ->
      records =
        if Enum.any?(entries, &match?(%{"TXT" => _}, &1)),
          do: Enum.flat_map(entries, &entry/1),
          else: Enum.flat_map(entries, &spf_as_txt/1)

      records = Enum.reject(records, &(&1 == {:txt, "NONE"}))

      if "TIMEOUT" in entries do
        given = records |> Enum.map(&elem(&1, 0)) |> MapSet.new()
        {name, records ++ for(t <- @types, t not in given, do: {t, :temperror})}
      else
        {name, records}
      end
    end)
  end

  defp spf_as_txt(%{"SPF" => value}), do: [txt: value]
  defp spf_as_txt(entry), do: entry(entry)

  defp entry(%{"TXT" => value}), do: [txt: value]
  defp entry(%{"SPF" => _}), do: []
  defp entry(%{"A" => ip}), do: [a: ip(ip)]
  defp entry(%{"AAAA" => ip}), do: [aaaa: ip(ip)]
  defp entry(%{"MX" => [pref, host]}), do: [mx: {pref, host}]
  defp entry(%{"PTR" => host}), do: [ptr: host]
  defp entry(%{"CNAME" => host}), do: [cname: host]
  defp entry("TIMEOUT"), do: []

  defp ip(s) do
    {:ok, ip} = s |> String.to_charlist() |> :inet.parse_address()
    ip
  end
end
