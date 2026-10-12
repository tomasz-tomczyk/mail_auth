defmodule MailAuth.PropertyTest do
  # Random input never makes a parser raise or hang, sign-then-verify always
  # passes, and canonicalizing twice gives the same bytes.
  use ExUnit.Case, async: true
  use ExUnitProperties

  # Long runs (STREAM_DATA_MAX_RUNS) take more than ExUnit's default 60
  # seconds per test. The workflow has its own time limit.
  @moduletag timeout: :infinity

  import MailAuth.Test.Helpers

  alias MailAuth.DKIM.Canonical

  @max_ms 1000

  defp quick(fun) do
    {time, result} = :timer.tc(fun)
    assert div(time, 1000) < @max_ms
    result
  end

  # Text made of the characters these formats care about, so the generators
  # reach past the first check.
  defp texty do
    one_of([
      binary(),
      string(:printable),
      list_of(
        member_of(
          ~w(; = : . @ / " \( \) < > , \\ % { } - _ + ~ v=DKIM1 v=DMARC1 v=spf1 p= a= b= h=
                     include: ip4: ip6: all mx ptr exists redirect= exp= %{d} %{i} dkim=pass
                     spf=fail header.d= reason= none) ++
            [" ", "\t", "\r\n", "\r\n ", "x", "1", "é"]
        ),
        max_length: 60
      )
      |> map(&Enum.join/1)
    ])
  end

  property "tag lists" do
    check all(s <- texty()) do
      quick(fn -> MailAuth.Tags.parse(s) end)
    end
  end

  property "DKIM key records" do
    check all(s <- texty()) do
      quick(fn -> MailAuth.DKIM.Key.parse(s) end)
    end
  end

  property "DMARC records" do
    check all(s <- texty()) do
      quick(fn -> MailAuth.DMARC.Record.parse(s) end)
    end
  end

  property "SPF records and macros" do
    check all(s <- texty()) do
      quick(fn ->
        MailAuth.SPF.Record.parse("v=spf1 " <> s)
        MailAuth.SPF.Macro.parse(s)
        MailAuth.SPF.Macro.parse(s, exp: true)
      end)
    end
  end

  property "Authentication-Results" do
    check all(s <- texty()) do
      quick(fn ->
        MailAuth.AuthenticationResults.parse(s)
        MailAuth.AuthenticationResults.parse("Authentication-Results: " <> s, trusted: ["x"])
      end)
    end
  end

  property "headers and addresses" do
    check all(s <- texty()) do
      quick(fn ->
        MailAuth.Message.parse(s)
        MailAuth.Address.list(s)
      end)
    end
  end

  property "DMARC reports" do
    check all(s <- texty()) do
      quick(fn ->
        MailAuth.DMARC.Report.parse(s)
        MailAuth.DMARC.Report.parse("<feedback>" <> s <> "</feedback>")
        MailAuth.DMARC.Report.parse(:zlib.gzip(s))
      end)
    end
  end

  property "DKIM verify with random signatures" do
    check all(s <- texty(), body <- texty()) do
      raw =
        "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s1; h=from; bh=; b=;" <>
          s <> "\r\n" <> message() <> body

      results = quick(fn -> MailAuth.DKIM.verify(raw, static(key_record("example.com"))) end)
      assert is_list(results)
    end
  end

  property "SPF with random records" do
    check all(s <- texty()) do
      records = %{"example.com" => [txt: "v=spf1 " <> s], "a.example.com" => [txt: s]}

      result =
        quick(fn ->
          MailAuth.SPF.check("192.0.2.1", "a@example.com", "mx.example.com", static(records))
        end)

      assert result.result in [:pass, :fail, :softfail, :neutral, :none, :temperror, :permerror]
    end
  end

  property "canonicalizing twice gives the same bytes" do
    check all(s <- texty()) do
      s = MailAuth.Message.normalize_line_endings(s)

      for algorithm <- [:simple, :relaxed] do
        once = Canonical.body(s, algorithm)
        assert Canonical.body(once, algorithm) == once
      end

      header = "X-Test: " <> s
      once = Canonical.header(header, :relaxed)
      assert Canonical.header(once, :relaxed) == once
    end
  end

  property "sign then verify always passes" do
    header_value = string(:printable, max_length: 80) |> map(&String.replace(&1, ~r/[\r\n]/, " "))

    check all(
            subject <- header_value,
            body <- texty(),
            canonicalization <-
              member_of([
                {:relaxed, :relaxed},
                {:simple, :simple},
                {:relaxed, :simple},
                {:simple, :relaxed}
              ])
          ) do
      raw = "From: a@example.com\r\nTo: b@example.net\r\nSubject: #{subject}\r\n\r\n" <> body
      signed = sign(raw, "example.com", canonicalization: canonicalization)
      assert [%{result: :pass}] = MailAuth.DKIM.verify(signed, static(key_record("example.com")))
    end
  end
end
