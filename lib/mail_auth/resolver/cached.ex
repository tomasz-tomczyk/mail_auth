defmodule MailAuth.Resolver.Cached do
  @moduledoc """
  A resolver that wraps another one with an ETS cache.

  Answers are kept for their TTL, capped at one hour. "No such name" and "no
  such record" answers are kept too, as RFC 2308 says. Temporary failures are
  not kept.

  Start it in your supervision tree:

      children = [
        {MailAuth.Resolver.Cached, resolver: MailAuth.Resolver.Inet, max_size: 10_000}
      ]

  and use it:

      MailAuth.authenticate(raw, resolver: MailAuth.Resolver.Cached)

  Options for `start_link/1`:

    * `:name`: the cache's name. Default `MailAuth.Resolver.Cached`. With
      another name, pass `cache: name` to every call
    * `:resolver`: the resolver to ask on a miss. Default `MailAuth.Resolver.Inet`
    * `:max_size`: the most answers to keep. Default 10 000
    * `:max_ttl`: the longest time to keep an answer, in seconds. Default 3600

  When the cache is full, expired answers are removed first; if it is still
  full, the oldest answers go.
  """

  @behaviour MailAuth.Resolver

  use GenServer

  @default_max_size 10_000
  @default_max_ttl 3600

  @doc "Starts the cache."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, Keyword.put(opts, :name, name), name: name)
  end

  @doc false
  def child_spec(opts) do
    %{
      id: Keyword.get(opts, :name, __MODULE__),
      start: {__MODULE__, :start_link, [opts]}
    }
  end

  @doc "Removes every answer from the cache."
  @spec clear(atom()) :: :ok
  def clear(name \\ __MODULE__), do: GenServer.call(name, :clear)

  @impl MailAuth.Resolver
  def lookup(name, type, opts) do
    table = Keyword.get(opts, :cache, __MODULE__)
    key = {name, type}
    now = System.monotonic_time(:second)

    case :ets.lookup(table, key) do
      [{^key, expires, answer, _inserted}] when expires > now ->
        remaining_ttl(answer, expires - now)

      _ ->
        [{:config, resolver, max_ttl, max_size}] = :ets.lookup(table, :config)
        answer = resolver.lookup(name, type, opts)
        store(table, key, answer, now, max_ttl, max_size)
        answer
    end
  end

  defp remaining_ttl({:ok, records, _}, ttl), do: {:ok, records, ttl}
  defp remaining_ttl({:error, reason, _}, ttl), do: {:error, reason, ttl}

  defp store(_table, _key, {:error, :temperror, _}, _now, _max_ttl, _max_size), do: :ok

  defp store(table, key, answer, now, max_ttl, max_size) do
    ttl = answer |> elem(2) |> min(max_ttl)

    if ttl > 0 do
      if :ets.info(table, :size) > max_size, do: GenServer.cast(table, :prune)
      :ets.insert(table, {key, now + ttl, answer, System.monotonic_time()})
    end

    :ok
  end

  @impl GenServer
  def init(opts) do
    table = :ets.new(Keyword.fetch!(opts, :name), [:named_table, :public, read_concurrency: true])

    :ets.insert(
      table,
      {:config, Keyword.get(opts, :resolver, MailAuth.Resolver.Inet),
       Keyword.get(opts, :max_ttl, @default_max_ttl),
       Keyword.get(opts, :max_size, @default_max_size)}
    )

    {:ok, table}
  end

  @impl GenServer
  def handle_call(:clear, _from, table) do
    :ets.select_delete(table, [{{{:_, :_}, :_, :_, :_}, [], [true]}])
    {:reply, :ok, table}
  end

  @impl GenServer
  def handle_cast(:prune, table) do
    [{:config, _, _, max_size}] = :ets.lookup(table, :config)
    now = System.monotonic_time(:second)
    :ets.select_delete(table, [{{{:_, :_}, :"$1", :_, :_}, [{:"=<", :"$1", now}], [true]}])

    excess = :ets.info(table, :size) - 1 - max_size

    if excess > 0 do
      table
      |> :ets.select([{{:"$1", :_, :_, :"$2"}, [{:is_tuple, :"$1"}], [{{:"$2", :"$1"}}]}])
      |> Enum.sort()
      |> Enum.take(excess + div(max_size, 10))
      |> Enum.each(fn {_, key} -> :ets.delete(table, key) end)
    end

    {:noreply, table}
  end
end
