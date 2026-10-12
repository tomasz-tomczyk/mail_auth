defmodule MailAuth.DKIM.CanonicalTest do
  # Canonicalization tables (RFC 6376 section 3.4).
  use ExUnit.Case, async: true

  alias MailAuth.DKIM.Canonical

  import MailAuth.Test.Helpers

  defp body(raw, algorithm),
    do: raw |> MailAuth.Message.normalize_line_endings() |> Canonical.body(algorithm)

  for {input, expected} <- [
        {"", "\r\n"},
        {"\r\n", "\r\n"},
        {"\r\n\r\n\r\n", "\r\n"},
        {"Hey\r\n\r\n", "Hey\r\n"},
        {"Hey\r\nHow r u?\r\n\r\n\r\n", "Hey\r\nHow r u?\r\n"},
        {"Hey\r\n\r\nHow r u?", "Hey\r\n\r\nHow r u?\r\n"},
        {"What about\nLF endings?\n\n", "What about\r\nLF endings?\r\n"},
        {"\r\n\r\n", "\r\n"},
        {"\r\n\r", "\r\n\r\r\n"},
        {"\r\n\r\nhey\n\n", "\r\n\r\nhey\r\n"}
      ] do
    test "simple body #{inspect(input)}" do
      assert body(unquote(input), :simple) == unquote(expected)
    end
  end

  for {input, expected} <- [
        {"", ""},
        {"\r\n", ""},
        {"\r\n\r\n\r\n", ""},
        {"Hey\r\n\r\n", "Hey\r\n"},
        {"Hey\r\nHow r u?\r\n\r\n\r\n", "Hey\r\nHow r u?\r\n"},
        {"Hey\r\n\r\nHow r u?", "Hey\r\n\r\nHow r u?\r\n"},
        {"Hey \t you!", "Hey you!\r\n"},
        {"Hey \t \r\nyou!", "Hey\r\nyou!\r\n"},
        {"Hey\r\n \t you!\r\n", "Hey\r\n you!\r\n"},
        {"Hey\r\n \t \r\n \r\n", "Hey\r\n"}
      ] do
    test "relaxed body #{inspect(input)}" do
      assert body(unquote(input), :relaxed) == unquote(expected)
    end
  end

  for {input, expected} <- [
        {"SubjeCT: Your Name\r\n", "subject:Your Name\r\n"},
        {"Subject \t:\t Your Name\t \r\n", "subject:Your Name\r\n"},
        {"Subject \t:\t Kimi \t \r\n No \t\r\n Na Wa\r\n", "subject:Kimi No Na Wa\r\n"},
        {"Subject \t:\t Ki \tmi \t \r\n No \t\r\n Na Wa\r\n", "subject:Ki mi No Na Wa\r\n"}
      ] do
    test "relaxed header #{inspect(input)}" do
      assert Canonical.header(unquote(input), :relaxed) == unquote(expected)
    end
  end

  test "simple headers are unchanged" do
    assert Canonical.header("SubjeCT : Your  Name\r\n", :simple) == "SubjeCT : Your  Name\r\n"
  end

  describe "the example of RFC 6376 section 3.4.5" do
    @headers ["A: X\r\n", "B : Y\t\r\n\tZ  \r\n"]
    @body " C \r\nD \t E\r\n\r\n\r\n"

    test "relaxed" do
      assert Enum.map(@headers, &Canonical.header(&1, :relaxed)) == ["a:X\r\n", "b:Y Z\r\n"]
      assert Canonical.body(@body, :relaxed) == " C\r\nD E\r\n"
    end

    test "simple" do
      assert Enum.map(@headers, &Canonical.header(&1, :simple)) == @headers
      assert Canonical.body(@body, :simple) == " C \r\nD \t E\r\n"
    end
  end

  test "a bare LF in the body ends a line, as CRLF does" do
    assert Canonical.body("a \nb\n\n", :relaxed) == "a\r\nb\r\n"
    assert Canonical.body("a \nb\n\n", :simple) == "a \r\nb\r\n"
    assert Canonical.body("a\r\r\n\n", :simple) == "a\r\r\n"
  end

  describe "body_hash" do
    test "hashes the canonical body and gives its length" do
      for algorithm <- [:simple, :relaxed], hash <- [:sha, :sha256] do
        canonical = Canonical.body(@body, algorithm)
        length = byte_size(canonical)

        assert {:ok, :crypto.hash(hash, canonical), length} ==
                 Canonical.body_hash(@body, algorithm, hash, nil)
      end
    end

    test "with l=, hashes the first l bytes" do
      assert {:ok, digest, 3} = Canonical.body_hash(@body, :relaxed, :sha256, 3)
      assert digest == :crypto.hash(:sha256, " C\r")

      assert {:ok, digest, 0} = Canonical.body_hash("", :simple, :sha256, 0)
      assert digest == :crypto.hash(:sha256, "")

      assert {:ok, _, 2} = Canonical.body_hash("", :simple, :sha256, 2)
      assert {:ok, _, 0} = Canonical.body_hash("", :relaxed, :sha256, 0)
    end

    test "with l= longer than the canonical body" do
      assert {:error, :body_length_exceeds} = Canonical.body_hash(@body, :relaxed, :sha256, 10)
      assert {:error, :body_length_exceeds} = Canonical.body_hash("", :relaxed, :sha256, 1)
      assert {:error, :body_length_exceeds} = Canonical.body_hash("\r\n\r\n", :simple, :sha256, 3)
    end
  end

  describe "a large body" do
    # About 50 MB of heap. Before 0.1.1, relaxed canonicalization of a body
    # of empty lines built a list of every line, used about 2 GB and took
    # over 7 seconds. Now each call takes about 0.3 seconds on a laptop; the
    # time limit leaves room for slow CI runners.
    @max_ms 2000
    @max_heap_words div(50 * 1024 * 1024, :erlang.system_info(:wordsize))
    @size 20 * 1024 * 1024

    # Runs `fun` in a process that is killed past the heap limit, and
    # returns its result and the time it took in milliseconds.
    defp limited(fun) do
      {pid, ref} =
        spawn_monitor(fn ->
          Process.flag(:max_heap_size, %{size: @max_heap_words, kill: true, error_logger: false})
          {time, result} = :timer.tc(fun)
          exit({:done, result, div(time, 1000)})
        end)

      assert_receive {:DOWN, ^ref, :process, ^pid, reason}, 30_000
      assert {:done, result, ms} = reason
      {result, ms}
    end

    for {name, line} <- [crlf: "\r\n", lf: "\n"] do
      test "of empty lines ending in #{name}" do
        body = String.duplicate(unquote(line), div(@size, byte_size(unquote(line))))

        for algorithm <- [:simple, :relaxed], limit <- [nil, 10, @size] do
          {result, ms} = limited(fn -> Canonical.body_hash(body, algorithm, :sha256, limit) end)

          case {algorithm, limit} do
            {:simple, nil} -> assert {:ok, _, 2} = result
            {:relaxed, nil} -> assert {:ok, _, 0} = result
            _ -> assert {:error, :body_length_exceeds} = result
          end

          assert ms < @max_ms
        end
      end
    end

    test "of empty lines followed by text" do
      body = String.duplicate("\n", @size) <> "x"

      for algorithm <- [:simple, :relaxed] do
        {result, ms} = limited(fn -> Canonical.body_hash(body, algorithm, :sha256, nil) end)
        assert {:ok, _, length} = result
        assert length == 2 * @size + 3
        assert ms < @max_ms
      end
    end

    test "of whitespace" do
      body = String.duplicate(" \tx\n", div(@size, 4))

      {result, ms} = limited(fn -> Canonical.body_hash(body, :relaxed, :sha256, nil) end)
      assert {:ok, _, length} = result
      assert length == div(@size, 4) * 4
      assert ms < @max_ms
    end

    test "in authenticate/2" do
      raw = sign(message(), "example.com")

      # Text after the empty lines, so the body hash does not match.
      for line <- ["\r\n", "\n"] do
        raw = raw <> String.duplicate(line, div(@size, byte_size(line))) <> "x"
        opts = static(key_record("example.com"))

        {result, ms} = limited(fn -> MailAuth.authenticate(raw, opts) end)
        assert [%{result: :fail, reason: :body_hash_mismatch}] = result.dkim
        assert ms < @max_ms
      end
    end
  end
end
