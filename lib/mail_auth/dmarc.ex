defmodule MailAuth.DMARC do
  @moduledoc """
  DMARC (RFC 9989): checks that a DKIM signature or the SPF check that passed
  belongs to the domain in the `From:` address, and reads the policy the
  domain publishes.

  The organizational domain is found with RFC 9989's DNS tree walk, so no
  copy of the Public Suffix List is needed. A caller who wants the list's
  answers passes `:organizational_domain`.

  ## Options

    * `:spf`: the `MailAuth.SPF.Result` of the message, if SPF ran
    * `:organizational_domain`: a function `(domain, opts) -> {:ok, org} |
      {:error, reason}` used instead of the tree walk. With it, the record is
      looked up at the From domain and then at its organizational domain, as
      RFC 7489 did
    * `:resolver`, `:deadline`, `:timeout`: see `MailAuth.Resolver` and `MailAuth`
  """

  alias MailAuth.{Address, DNS, Domain, Message}
  alias MailAuth.DMARC.{Record, Result}

  @max_queries 8

  @doc """
  Evaluates DMARC for `raw`, given its DKIM results and, in `opts[:spf]`, its
  SPF result.
  """
  @spec evaluate(binary(), [MailAuth.DKIM.Result.t()], keyword()) :: Result.t()
  def evaluate(raw, dkim_results, opts \\ []) when is_binary(raw) do
    case Message.parse(raw) do
      {:ok, msg} -> evaluate_message(msg, dkim_results, opts)
      {:error, reason} -> %Result{result: :permerror, reason: reason}
    end
  end

  @doc false
  @spec evaluate_message(Message.t(), [MailAuth.DKIM.Result.t()], keyword()) :: Result.t()
  def evaluate_message(msg, dkim_results, opts) do
    opts = DNS.start(opts)

    :telemetry.span([:mail_auth, :dmarc], %{}, fn ->
      result =
        case from_domain(msg) do
          {:ok, from} -> evaluate_domain(from, dkim_results, opts)
          {:error, reason} -> %Result{result: :permerror, reason: reason}
        end

      {result, %{result: result.result}}
    end)
  end

  @doc false
  @spec from_domain(Message.t()) :: {:ok, String.t()} | {:error, atom()}
  def from_domain(msg) do
    case Message.get_all(msg, "from") do
      [] ->
        {:error, :no_from}

      [raw] ->
        case raw |> Message.unfolded_value() |> Address.list() do
          [] -> {:error, :invalid_from}
          [addr] -> addr |> Address.domain() |> ascii_from()
          _ -> {:error, :multiple_authors}
        end

      _ ->
        {:error, :multiple_from}
    end
  end

  defp ascii_from(nil), do: {:error, :invalid_from}

  defp ascii_from(domain) do
    with {:ok, ascii} <- Domain.to_ascii(domain),
         true <- valid_domain?(ascii) do
      {:ok, ascii}
    else
      _ -> {:error, :invalid_from}
    end
  end

  defp valid_domain?(domain) do
    labels = String.split(domain, ".")

    domain != "" and byte_size(domain) <= 253 and
      Enum.all?(labels, &(&1 != "" and byte_size(&1) <= 63)) and
      not String.starts_with?(domain, "[")
  end

  defp evaluate_domain(from, dkim_results, opts) do
    base = %Result{from_domain: from}

    case policy_record(from, opts, %{}) do
      {:error, reason, _walks} ->
        %{base | result: :temperror, reason: reason}

      {:none, org, _walks} ->
        %{base | result: :none, reason: :no_record, organizational_domain: org}

      {:ok, record, org, walks} ->
        cond do
          Record.valid_policy?(record) ->
            apply_record(base, record, org, walks, dkim_results, opts)

          Enum.any?(record.rua, &String.starts_with?(String.downcase(&1), "mailto:")) ->
            record = %{record | p: :none, sp: nil, np: nil}
            apply_record(base, record, org, walks, dkim_results, opts)

          true ->
            %{
              base
              | result: :none,
                reason: :invalid_record,
                organizational_domain: org,
                record_domain: record.domain,
                record: record,
                warnings: record.warnings
            }
        end
    end
  end

  defp apply_record(base, record, org, walks, dkim_results, opts) do
    result = %{
      base
      | organizational_domain: org,
        record_domain: record.domain,
        record: record,
        policy: applicable_policy(record, base.from_domain, opts),
        testing?: record.testing?,
        warnings: record.warnings
    }

    align(result, record, dkim_results, opts[:spf], opts, walks)
  end

  # Finds the record that applies to `from`: its own, else its
  # organizational domain's, else the one found highest up.
  defp policy_record(from, opts, walks) do
    case walk(from, opts, walks) do
      {:ok, found, walks} ->
        org = organizational(found, from, opts)

        case found do
          [] ->
            {:none, org, walks}

          _ ->
            record =
              Enum.find_value(found, fn {name, r} -> name == from && r end) ||
                Enum.find_value(found, fn {name, r} -> name == org && r end) ||
                found |> List.last() |> elem(1)

            {:ok, record, org, walks}
        end

      {:error, reason, walks} ->
        {:error, reason, walks}
    end
  end

  # The DNS tree walk of RFC 9989 section 4.10: _dmarc.<name> for the name
  # and each parent, at most 8 queries. Results are kept in `walks` for the
  # rest of the call.
  defp walk(domain, opts, walks) do
    answer =
      case Map.fetch(walks, domain) do
        {:ok, answer} -> answer
        :error -> do_walk(domain, opts)
      end

    walks = Map.put(walks, domain, answer)

    case answer do
      {:ok, found} -> {:ok, found, walks}
      {:error, reason} -> {:error, reason, walks}
    end
  end

  defp do_walk(domain, opts) do
    domain
    |> walk_names(opts)
    |> Enum.reduce_while({:ok, []}, fn name, {:ok, found} ->
      case record_at(name, opts) do
        {:ok, record} ->
          found = [{name, record} | found]
          if record.psd in [:yes, :no], do: {:halt, {:ok, found}}, else: {:cont, {:ok, found}}

        :none ->
          {:cont, {:ok, found}}

        {:error, reason} ->
          {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, found} -> {:ok, Enum.reverse(found)}
      error -> error
    end
  end

  defp walk_names(domain, opts) do
    case Keyword.get(opts, :organizational_domain) do
      nil ->
        labels = Domain.labels(domain)
        n = length(labels)

        n
        |> Stream.iterate(fn count -> if count >= 8, do: 7, else: count - 1 end)
        |> Stream.take_while(&(&1 >= 1))
        |> Enum.take(@max_queries)
        |> Enum.map(fn count -> labels |> Enum.take(-count) |> Enum.join(".") end)

      fun ->
        case fun.(domain, opts) do
          {:ok, org} -> Enum.uniq([domain, Domain.to_ascii!(org)])
          _ -> [domain]
        end
    end
  end

  defp record_at(name, opts) do
    case DNS.lookup("_dmarc." <> name, :txt, opts) do
      {:ok, txts} ->
        case for(txt <- txts, {:ok, r} <- [Record.parse(txt, name)], do: r) do
          [record] -> {:ok, record}
          _ -> :none
        end

      {:error, reason} when reason in [:nxdomain, :no_data] ->
        :none

      {:error, :deadline} ->
        {:error, :deadline}

      {:error, :temperror} ->
        {:error, :dns_error}
    end
  end

  # RFC 9989 section 4.10.2, from the longest name found to the shortest.
  defp organizational(found, start, opts) do
    case Keyword.get(opts, :organizational_domain) do
      nil ->
        Enum.find_value(found, fn
          {name, %{psd: :no}} -> name
          {name, %{psd: :yes}} when name != start -> one_label_below(name, start)
          _ -> nil
        end) ||
          case List.last(found) do
            {name, _} -> name
            nil -> start
          end

      fun ->
        case fun.(start, opts) do
          {:ok, org} -> Domain.to_ascii!(org)
          _ -> start
        end
    end
  end

  defp one_label_below(name, start) do
    depth = length(Domain.labels(name)) + 1
    start |> Domain.labels() |> Enum.take(-depth) |> Enum.join(".")
  end

  # p at the From domain; below it, sp, or np when the From domain does not
  # exist. np falls back to sp, and sp to p. A missing p is read as none.
  defp applicable_policy(record, from, opts) do
    policy =
      if record.domain == from do
        record.p
      else
        sp = record.sp || record.p
        np = record.np || sp
        if np != sp and not exists?(from, opts), do: np, else: sp
      end

    policy || :none
  end

  # A domain does not exist when its A, AAAA and MX queries all say NXDOMAIN.
  defp exists?(domain, opts) do
    not Enum.all?([:a, :aaaa, :mx], fn type ->
      DNS.lookup(domain, type, opts) == {:error, :nxdomain}
    end)
  end

  defp align(result, record, dkim_results, spf, opts, walks) do
    from = result.from_domain
    org = result.organizational_domain

    dkim =
      for %{result: r, domain: d} <- dkim_results, r in [:pass, :temperror], is_binary(d) do
        {:dkim, r, d, record.adkim}
      end

    spf_candidates =
      case spf do
        %{result: r, domain: d} when r in [:pass, :temperror] and is_binary(d) ->
          [{:spf, r, Domain.to_ascii!(d), record.aspf}]

        _ ->
          []
      end

    {checked, _walks} =
      Enum.map_reduce(dkim ++ spf_candidates, walks, fn {method, r, d, mode}, walks ->
        {aligned, walks} = aligned?(d, from, org, mode, opts, walks)

        status =
          case {r, aligned} do
            {:pass, true} -> :aligned
            {:pass, :error} -> :temp
            {:temperror, true} -> :temp
            _ -> :not_aligned
          end

        {{method, status, d}, walks}
      end)

    aligned_by = for {m, :aligned, _} <- checked, uniq: true, do: m

    dkim_domain =
      Enum.find_value(checked, fn {m, s, d} -> m == :dkim and s == :aligned and d end) ||
        Enum.find_value(dkim_results, fn %{result: r, domain: d} -> r == :pass and d end)

    result = %{
      result
      | aligned_by: aligned_by,
        dkim_domain: dkim_domain,
        spf_domain: spf && spf.domain && Domain.to_ascii!(spf.domain)
    }

    cond do
      aligned_by != [] ->
        %{result | result: :pass, disposition: :none}

      Enum.any?(checked, fn {_, s, _} -> s == :temp end) ->
        %{result | result: :temperror, reason: :dns_error}

      true ->
        %{result | result: :fail, reason: :not_aligned, disposition: disposition(result)}
    end
  end

  defp disposition(%{policy: policy, testing?: true}) do
    case policy do
      :reject -> :quarantine
      _ -> :none
    end
  end

  defp disposition(%{policy: policy}), do: policy || :none

  defp aligned?(domain, from, _org, _mode, _opts, walks) when domain == from, do: {true, walks}
  defp aligned?(_domain, _from, _org, :strict, _opts, walks), do: {false, walks}

  defp aligned?(domain, _from, org, :relaxed, opts, walks) do
    cond do
      not Domain.subdomain_of?(domain, org) ->
        {false, walks}

      Keyword.has_key?(opts, :organizational_domain) ->
        {organizational([], domain, opts) == org, walks}

      true ->
        case walk(domain, opts, walks) do
          {:ok, found, walks} -> {organizational(found, domain, opts) == org, walks}
          {:error, _reason, walks} -> {:error, walks}
        end
    end
  end

  @doc """
  Looks up the DMARC record that applies to `domain`.

  Returns the record (its `domain` field says where it was found) and the
  organizational domain.
  """
  @spec lookup(String.t(), keyword()) ::
          {:ok, Record.t(), String.t()}
          | {:error, :no_record | :dns_error | :deadline | :invalid_domain}
  def lookup(domain, opts \\ []) do
    opts = DNS.start(opts)

    with {:ok, domain} <- ascii_lookup(domain) do
      case policy_record(domain, opts, %{}) do
        {:ok, record, org, _} -> {:ok, record, org}
        {:none, _org, _} -> {:error, :no_record}
        {:error, reason, _} -> {:error, reason}
      end
    end
  end

  defp ascii_lookup(domain) do
    case Domain.to_ascii(domain) do
      {:ok, ascii} -> if valid_domain?(ascii), do: {:ok, ascii}, else: {:error, :invalid_domain}
      error -> error
    end
  end
end
