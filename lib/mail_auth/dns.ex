defmodule MailAuth.DNS do
  @moduledoc false

  # Every DNS query goes through here. This is where the `:deadline` and
  # `:timeout` limits, the TXT size limit and the telemetry events live.

  alias MailAuth.Domain

  @default_deadline 15_000
  @default_timeout 5_000
  @max_txt_bytes 4096

  @type error :: :nxdomain | :no_data | :temperror | :deadline

  @doc """
  Sets the deadline for a whole call, unless an outer call already set it.
  """
  @spec start(keyword()) :: keyword()
  def start(opts) do
    if Keyword.has_key?(opts, :deadline_at) do
      opts
    else
      deadline = Keyword.get(opts, :deadline, @default_deadline)
      Keyword.put(opts, :deadline_at, now() + deadline)
    end
  end

  @doc "True when the call's deadline has passed."
  @spec expired?(keyword()) :: boolean()
  def expired?(opts), do: remaining(opts) <= 0

  defp remaining(opts) do
    case Keyword.fetch(opts, :deadline_at) do
      {:ok, at} -> at - now()
      :error -> @default_deadline
    end
  end

  defp now, do: System.monotonic_time(:millisecond)

  @doc """
  Looks up `name`. Returns `{:ok, records}` or `{:error, reason}`, where
  `:deadline` means the call ran out of time.
  """
  @spec lookup(String.t(), MailAuth.Resolver.record_type(), keyword()) ::
          {:ok, [term()]} | {:error, error()}
  def lookup(name, type, opts) do
    case Domain.to_ascii(name) do
      {:ok, ""} -> {:error, :nxdomain}
      {:ok, ascii} -> timed_lookup(ascii, type, opts)
      {:error, _} -> {:error, :nxdomain}
    end
  end

  defp timed_lookup(name, type, opts) do
    left = remaining(opts)

    if left <= 0 do
      {:error, :deadline}
    else
      timeout = min(Keyword.get(opts, :timeout, @default_timeout), left)
      resolver = Keyword.get(opts, :resolver, MailAuth.Resolver.Inet)
      meta = %{name: name, type: type, resolver: resolver}

      :telemetry.span([:mail_auth, :dns, :lookup], meta, fn ->
        result = run(resolver, name, type, Keyword.put(opts, :timeout, timeout), timeout, left)
        {result, Map.put(meta, :result, telemetry_result(result))}
      end)
    end
  end

  defp run(resolver, name, type, opts, timeout, left) do
    task = Task.async(fn -> safe_lookup(resolver, name, type, opts) end)

    case Task.yield(task, timeout + 50) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> normalize(result, type)
      _ when timeout >= left -> {:error, :deadline}
      _ -> {:error, :temperror}
    end
  end

  defp safe_lookup(resolver, name, type, opts) do
    resolver.lookup(name, type, opts)
  rescue
    _ -> {:error, :temperror, 0}
  catch
    _, _ -> {:error, :temperror, 0}
  end

  defp normalize({:ok, records, _ttl}, :txt) when is_list(records) do
    records
    |> Enum.filter(&(is_binary(&1) and byte_size(&1) <= @max_txt_bytes))
    |> non_empty()
  end

  defp normalize({:ok, records, _ttl}, _type) when is_list(records), do: non_empty(records)

  defp normalize({:error, reason, _ttl}, _type) when reason in [:nxdomain, :no_data, :temperror],
    do: {:error, reason}

  defp normalize(_other, _type), do: {:error, :temperror}

  defp non_empty([]), do: {:error, :no_data}
  defp non_empty(records), do: {:ok, records}

  defp telemetry_result({:ok, _}), do: :ok
  defp telemetry_result({:error, reason}), do: reason
end
