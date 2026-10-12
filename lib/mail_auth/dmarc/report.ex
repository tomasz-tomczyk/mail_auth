defmodule MailAuth.DMARC.Report do
  @moduledoc """
  Reads DMARC aggregate reports (RFC 9990), as mail providers send them:
  XML, gzip or zip. Reports in the older RFC 7489 format read the same way.

      {:ok, report} = MailAuth.DMARC.Report.parse(File.read!("report.xml.gz"))
      report.policy_published.domain
      for record <- report.records, do: {record.source_ip, record.count, record.disposition}

  Reports come from strangers, so the input is bounded: at most 50 MB once
  uncompressed, and no DTD (`<!DOCTYPE`), which rules out entity expansion
  attacks. Element names never become atoms.

  ## Fields

    * `:version`: the report format version, when given
    * `:metadata`: `:org_name`, `:email`, `:extra_contact_info`, `:report_id`,
      `:begin` and `:end` (as `DateTime`), `:generator`, `:errors`
    * `:policy_published`: the record the reporter found: `:domain`, `:p`,
      `:sp`, `:np`, `:adkim`, `:aspf`, `:testing`, `:discovery_method`,
      `:fo`, `:pct`, as written
    * `:records`: one map per row: `:source_ip`, `:count`, `:disposition`,
      `:dkim`, `:spf` (the policy evaluation), `:reasons`, `:header_from`,
      `:envelope_from`, `:envelope_to`, and `:auth_results` with `:dkim` and
      `:spf` lists

  Values are strings as written, except `:count` and the dates.
  """

  @max_bytes 50 * 1024 * 1024

  @type t :: %__MODULE__{
          version: String.t() | nil,
          metadata: map(),
          policy_published: map(),
          records: [map()]
        }

  defstruct version: nil, metadata: %{}, policy_published: %{}, records: []

  @doc "Parses a report: XML, or XML in gzip or zip."
  @spec parse(binary()) :: {:ok, t()} | {:error, atom()}
  def parse(<<0x1F, 0x8B, _::binary>> = gzip),
    do: with({:ok, xml} <- gunzip(gzip), do: parse_xml(xml))

  def parse(<<"PK", 3, 4, _::binary>> = zip),
    do: with({:ok, xml} <- unzip(zip), do: parse_xml(xml))

  def parse(xml) when is_binary(xml), do: parse_xml(xml)

  defp gunzip(data) do
    z = :zlib.open()

    try do
      :ok = :zlib.inflateInit(z, 31)
      inflate(z, :zlib.safeInflate(z, data), [], 0)
    rescue
      _ -> {:error, :invalid_gzip}
    catch
      _, _ -> {:error, :invalid_gzip}
    after
      :zlib.close(z)
    end
  end

  defp inflate(_z, _step, _acc, size) when size > @max_bytes, do: {:error, :too_large}

  defp inflate(z, {:continue, out}, acc, size),
    do: inflate(z, :zlib.safeInflate(z, []), [acc | out], size + IO.iodata_length(out))

  defp inflate(_z, {:finished, out}, acc, size) do
    if size + IO.iodata_length(out) > @max_bytes,
      do: {:error, :too_large},
      else: {:ok, IO.iodata_to_binary([acc | out])}
  end

  defp unzip(zip) do
    with {:ok, [_comment | entries]} <- :zip.list_dir(zip),
         [{:zip_file, name, info, _, _, _} | _] <-
           Enum.filter(entries, &match?({:zip_file, _, _, _, _, _}, &1)),
         true <- elem(info, 1) <= @max_bytes,
         {:ok, [{_, xml}]} <- :zip.unzip(zip, [:memory, {:file_list, [name]}]) do
      if byte_size(xml) > @max_bytes, do: {:error, :too_large}, else: {:ok, xml}
    else
      false -> {:error, :too_large}
      _ -> {:error, :invalid_zip}
    end
  rescue
    _ -> {:error, :invalid_zip}
  end

  defp parse_xml(xml) when byte_size(xml) > @max_bytes, do: {:error, :too_large}

  defp parse_xml(xml) do
    if Regex.match?(~r/<!DOCTYPE|<!ENTITY/i, xml) do
      {:error, :doctype_not_allowed}
    else
      case tree(xml) do
        {:ok, {"feedback", _attrs, children}} -> {:ok, build(children)}
        {:ok, _other} -> {:error, :not_a_report}
        :error -> {:error, :invalid_xml}
      end
    end
  end

  # Builds {name, attrs, children} elements with string names and text.
  defp tree(xml) do
    fun = fn
      {:startElement, _uri, local, _qname, _attrs}, _loc, stack ->
        [{to_string(local), [], []} | stack]

      {:characters, chars}, _loc, [{name, attrs, children} | rest] ->
        [{name, attrs, [IO.chardata_to_string(chars) | children]} | rest]

      {:endElement, _uri, _local, _qname}, _loc, [{name, attrs, children}, {pn, pa, pc} | rest] ->
        [{pn, pa, [{name, attrs, Enum.reverse(children)} | pc]} | rest]

      {:endElement, _uri, _local, _qname}, _loc, [{name, attrs, children}] ->
        [{:done, {name, attrs, Enum.reverse(children)}}]

      _event, _loc, stack ->
        stack
    end

    opts = [
      event_fun: fun,
      event_state: [],
      external_entities: :none,
      fail_undeclared_ref: true
    ]

    case :xmerl_sax_parser.stream(xml, opts) do
      {:ok, [{:done, root}], _rest} -> {:ok, root}
      _ -> :error
    end
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  defp build(children) do
    metadata = child(children, "report_metadata")
    range = child(metadata, "date_range")
    policy = child(children, "policy_published")

    %__MODULE__{
      version: text(children, "version"),
      metadata: %{
        org_name: text(metadata, "org_name"),
        email: text(metadata, "email"),
        extra_contact_info: text(metadata, "extra_contact_info"),
        report_id: text(metadata, "report_id"),
        begin: time(text(range, "begin")),
        end: time(text(range, "end")),
        generator: text(metadata, "generator"),
        errors: texts(metadata, "error")
      },
      policy_published:
        Map.new(~w(domain p sp np adkim aspf testing discovery_method fo pct)a, fn key ->
          {key, text(policy, Atom.to_string(key))}
        end),
      records: for({"record", _, record} <- children, do: record(record))
    }
  end

  defp record(children) do
    row = child(children, "row")
    evaluated = child(row, "policy_evaluated")
    identifiers = child(children, "identifiers")
    auth = child(children, "auth_results")

    %{
      source_ip: text(row, "source_ip"),
      count: integer(text(row, "count")),
      disposition: text(evaluated, "disposition"),
      dkim: text(evaluated, "dkim"),
      spf: text(evaluated, "spf"),
      reasons:
        for {"reason", _, reason} <- evaluated do
          %{type: text(reason, "type"), comment: text(reason, "comment")}
        end,
      header_from: text(identifiers, "header_from"),
      envelope_from: text(identifiers, "envelope_from"),
      envelope_to: text(identifiers, "envelope_to"),
      auth_results: %{
        dkim:
          for {"dkim", _, d} <- auth do
            %{
              domain: text(d, "domain"),
              selector: text(d, "selector"),
              result: text(d, "result"),
              human_result: text(d, "human_result")
            }
          end,
        spf:
          for {"spf", _, s} <- auth do
            %{
              domain: text(s, "domain"),
              scope: text(s, "scope"),
              result: text(s, "result"),
              human_result: text(s, "human_result")
            }
          end
      }
    }
  end

  defp child(children, name) do
    Enum.find_value(children, [], fn
      {^name, _, grandchildren} -> grandchildren
      _ -> nil
    end)
  end

  defp text(children, name) do
    case for({^name, _, content} <- children, do: content) do
      [content | _] -> content |> Enum.filter(&is_binary/1) |> Enum.join() |> String.trim()
      [] -> nil
    end
  end

  defp texts(children, name) do
    for {^name, _, content} <- children,
        do: content |> Enum.filter(&is_binary/1) |> Enum.join() |> String.trim()
  end

  defp integer(nil), do: nil

  defp integer(s) do
    case Integer.parse(s) do
      {n, ""} -> n
      _ -> nil
    end
  end

  defp time(s) do
    with n when is_integer(n) <- integer(s),
         {:ok, dt} <- DateTime.from_unix(n),
         do: dt,
         else: (_ -> nil)
  end
end
