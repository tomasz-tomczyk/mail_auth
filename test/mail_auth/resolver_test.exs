defmodule MailAuth.ResolverTest do
  use ExUnit.Case, async: true

  alias MailAuth.Resolver.{Cached, Static}

  describe "Static" do
    test "answers, NXDOMAIN, no data and failures" do
      records = %{
        "Example.com." => [
          txt: ["v=spf1 ", "-all"],
          a: {192, 0, 2, 1},
          mx: {10, "MX.example.com."}
        ],
        "alias.example.com" => [cname: "example.com"],
        "broken.example" => :temperror
      }

      assert {:ok, ["v=spf1 -all"], _} = Static.lookup("example.com", :txt, records: records)

      assert {:ok, [{10, "mx.example.com"}], _} =
               Static.lookup("example.com", :mx, records: records)

      assert {:ok, [{192, 0, 2, 1}], _} = Static.lookup("alias.example.com", :a, records: records)
      assert {:error, :no_data, _} = Static.lookup("example.com", :aaaa, records: records)
      assert {:error, :nxdomain, _} = Static.lookup("other.example", :a, records: records)
      assert {:error, :temperror, _} = Static.lookup("broken.example", :a, records: records)
    end

    test "records set for the process are seen from tasks" do
      Static.put_records(%{"example.com" => [a: {192, 0, 2, 1}]})
      task = Task.async(fn -> Static.lookup("example.com", :a, []) end)
      assert {:ok, [{192, 0, 2, 1}], _} = Task.await(task)
    end

    test "parse_lines/1" do
      text = """
      # a comment
      s1._domainkey.example.com TXT "v=DKIM1; " "p=abc"
      example.com MX 10 mx.example.com
      mx.example.com A 192.0.2.1
      mx.example.com AAAA 2001:db8::1
      1.2.0.192.in-addr.arpa PTR mx.example.com
      plain.example TXT v=spf1 -all
      """

      assert {:ok, records} = Static.parse_lines(text)
      assert records["s1._domainkey.example.com"] == [txt: "v=DKIM1; p=abc"]
      assert records["example.com"] == [mx: {10, "mx.example.com"}]

      assert records["mx.example.com"] == [
               a: {192, 0, 2, 1},
               aaaa: {8193, 3512, 0, 0, 0, 0, 0, 1}
             ]

      assert records["plain.example"] == [txt: "v=spf1 -all"]
      assert {:error, {:bad_line, "x.example A nope"}} = Static.parse_lines("x.example A nope")
    end
  end

  describe "Cached" do
    defmodule Counting do
      @behaviour MailAuth.Resolver
      def lookup(name, type, opts) do
        send(opts[:test_pid], {:lookup, name, type})
        Static.lookup(name, type, opts)
      end
    end

    setup do
      name = :"cache_#{System.unique_integer([:positive])}"
      start_supervised!({Cached, name: name, resolver: Counting, max_size: 3})
      opts = [cache: name, test_pid: self(), records: %{"example.com" => [a: {192, 0, 2, 1}]}]
      %{name: name, opts: opts}
    end

    test "keeps answers and NXDOMAIN, not failures", %{name: name, opts: opts} do
      assert {:ok, _, _} = Cached.lookup("example.com", :a, opts)
      assert {:ok, _, _} = Cached.lookup("example.com", :a, opts)
      assert_received {:lookup, "example.com", :a}
      refute_received {:lookup, "example.com", :a}

      assert {:error, :nxdomain, _} = Cached.lookup("nope.example", :a, opts)
      assert {:error, :nxdomain, _} = Cached.lookup("nope.example", :a, opts)
      assert_received {:lookup, "nope.example", :a}
      refute_received {:lookup, "nope.example", :a}

      opts = Keyword.put(opts, :records, %{"bad.example" => :temperror})
      assert {:error, :temperror, _} = Cached.lookup("bad.example", :a, opts)
      assert {:error, :temperror, _} = Cached.lookup("bad.example", :a, opts)
      assert_received {:lookup, "bad.example", :a}
      assert_received {:lookup, "bad.example", :a}

      assert Cached.clear(name) == :ok

      assert {:ok, _, _} =
               Cached.lookup(
                 "example.com",
                 :a,
                 opts |> Keyword.put(:records, %{"example.com" => [a: {1, 1, 1, 1}]})
               )

      assert_received {:lookup, "example.com", :a}
    end

    test "stays near its size", %{name: name, opts: opts} do
      for i <- 1..20, do: Cached.lookup("n#{i}.example", :a, opts)
      :sys.get_state(name)
      assert :ets.info(name, :size) <= 5
    end

    test "works as the resolver of a check", %{opts: opts} do
      records = %{"_dmarc.example.com" => [txt: "v=DMARC1; p=reject"]}
      opts = Keyword.merge(opts, resolver: Cached, records: records)
      assert {:ok, %{p: :reject}, "example.com"} = MailAuth.DMARC.lookup("example.com", opts)
    end
  end

  describe "Inet" do
    @describetag :network

    test "reads a DKIM key, a DMARC record and MX records from real DNS" do
      assert {:ok, [txt | _], _} =
               MailAuth.Resolver.Inet.lookup("_dmarc.gmail.com", :txt, timeout: 5000)

      assert String.starts_with?(txt, "v=DMARC1")

      assert {:ok, mxs, _} = MailAuth.Resolver.Inet.lookup("gmail.com", :mx, timeout: 5000)
      assert Enum.all?(mxs, &match?({pref, host} when is_integer(pref) and is_binary(host), &1))

      missing = "no-such-name-#{System.unique_integer([:positive])}.gmail.com"
      assert {:error, :nxdomain, _} = MailAuth.Resolver.Inet.lookup(missing, :a, timeout: 5000)

      # A 2048-bit key needs EDNS0 or TCP.
      assert {:ok, [key], _} =
               MailAuth.Resolver.Inet.lookup("google._domainkey.github.com", :txt, timeout: 5000)

      assert String.contains?(key, "p=")
    end
  end
end
