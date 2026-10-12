defmodule MailAuth.DMARCTest do
  use ExUnit.Case, async: true

  import MailAuth.Test.Helpers

  alias MailAuth.DKIM
  alias MailAuth.DMARC
  alias MailAuth.DMARC.Record
  alias MailAuth.SPF

  defp dkim(domain, result \\ :pass), do: %DKIM.Result{result: result, domain: domain}
  defp spf(domain, result \\ :pass), do: %SPF.Result{result: result, domain: domain}

  defp evaluate(from, records, dkim, opts \\ []) do
    DMARC.evaluate(message(from), dkim, static(records, opts))
  end

  describe "Record.parse/2" do
    test "reads every tag" do
      assert {:ok, r} =
               Record.parse(
                 "v=DMARC1; p=reject; sp=quarantine; np=none; adkim=s; aspf=s; psd=n; t=y; " <>
                   "rua=mailto:a@example.com, mailto:b@example.com; ruf=mailto:c@example.com; fo=1"
               )

      assert r.p == :reject
      assert r.sp == :quarantine
      assert r.np == :none
      assert r.adkim == :strict
      assert r.aspf == :strict
      assert r.psd == :no
      assert r.testing?
      assert r.rua == ["mailto:a@example.com", "mailto:b@example.com"]
      assert r.ruf == ["mailto:c@example.com"]
      assert r.fo == "1"
      assert r.warnings == []
    end

    test "defaults" do
      assert {:ok, r} = Record.parse("v=DMARC1; p=none")

      assert {r.adkim, r.aspf, r.psd, r.testing?, r.sp, r.np} ==
               {:relaxed, :relaxed, :unknown, false, nil, nil}
    end

    test "v=DMARC1 must be the first tag" do
      assert Record.parse("p=reject; v=DMARC1") == :error
      assert Record.parse("v=DMARC2; p=reject") == :error
      assert Record.parse("v=spf1 -all") == :error
    end

    test "removed and unknown tags are ignored" do
      assert {:ok, %{p: :reject, warnings: []}} =
               Record.parse("v=DMARC1; p=reject; pct=50; rf=afrf; ri=86400; xyz=1")
    end

    test "a missing or bad p is a warning" do
      assert {:ok, %{p: nil, warnings: [:missing_policy]}} =
               Record.parse("v=DMARC1; rua=mailto:a@b.c")

      assert {:ok, %{p: nil, warnings: [:invalid_policy]}} = Record.parse("v=DMARC1; p=bounce")
      assert {:ok, %{warnings: [:invalid_policy]}} = Record.parse("v=DMARC1; p=none; sp=maybe")
    end
  end

  describe "the From domain" do
    test "no From" do
      raw = "To: a@example.com\r\n\r\nhi\r\n"
      assert %{result: :permerror, reason: :no_from} = DMARC.evaluate(raw, [], static(%{}))
    end

    test "two From headers" do
      raw = "From: a@example.com\r\nFrom: b@evil.example\r\n\r\nhi\r\n"
      assert %{result: :permerror, reason: :multiple_from} = DMARC.evaluate(raw, [], static(%{}))
    end

    test "two authors in one From" do
      raw = "From: a@example.com, b@example.org\r\n\r\nhi\r\n"

      assert %{result: :permerror, reason: :multiple_authors} =
               DMARC.evaluate(raw, [], static(%{}))
    end

    test "no domain" do
      raw = "From: undisclosed-recipients:;\r\n\r\nhi\r\n"
      assert %{result: :permerror, reason: :invalid_from} = DMARC.evaluate(raw, [], static(%{}))
    end

    test "display names, comments and quotes" do
      records = %{"_dmarc.example.com" => [txt: "v=DMARC1; p=reject"]}

      for from <- [
            ~s("Joe, the <boss>" <joe@example.com>),
            "joe@evil.example (not really) <joe@example.com>",
            "Joe (comment, with comma) <joe@Example.COM>",
            "joe@example.com"
          ] do
        raw = "From: #{from}\r\n\r\nhi\r\n"
        result = DMARC.evaluate(raw, [dkim("example.com")], static(records))
        assert result.from_domain == "example.com", from
        assert result.result == :pass, from
      end
    end
  end

  describe "the DNS tree walk" do
    test "queries at most 8 names, as in RFC 9989 section 4.10" do
      {result, queries} =
        capture_queries(fn -> evaluate("a@a.b.c.d.e.f.g.h.i.j.mail.example.com", %{}, []) end)

      assert result.result == :none
      assert result.reason == :no_record

      assert Enum.map(queries, &elem(&1, 0)) == [
               "_dmarc.a.b.c.d.e.f.g.h.i.j.mail.example.com",
               "_dmarc.g.h.i.j.mail.example.com",
               "_dmarc.h.i.j.mail.example.com",
               "_dmarc.i.j.mail.example.com",
               "_dmarc.j.mail.example.com",
               "_dmarc.mail.example.com",
               "_dmarc.example.com",
               "_dmarc.com"
             ]
    end

    test "several valid records at one name are all thrown away" do
      records = %{
        "_dmarc.example.com" => [txt: "v=DMARC1; p=reject", txt: "v=DMARC1; p=none"],
        "_dmarc.com" => [txt: "v=DMARC1; p=quarantine; psd=y"]
      }

      result = evaluate("a@example.com", records, [])
      assert result.record_domain == "com"
      assert result.organizational_domain == "example.com"
    end

    test "records not starting with v=DMARC1 are not counted" do
      records = %{"_dmarc.example.com" => [txt: "v=spf1 -all", txt: "v=DMARC1; p=reject"]}

      assert %{record_domain: "example.com", policy: :reject} =
               evaluate("a@example.com", records, [])
    end

    test "B.4.1: simple organizational and policy example" do
      records = %{
        "_dmarc.example.com" => [txt: "v=DMARC1; p=reject"],
        "_dmarc.signing.example.com" => [txt: "v=DMARC1; p=reject"]
      }

      result =
        evaluate("a@example.com", records, [dkim("signing.example.com")], spf: spf("example.com"))

      assert result.result == :pass
      assert result.organizational_domain == "example.com"
      assert result.record_domain == "example.com"
      assert result.aligned_by == [:dkim, :spf]
    end

    test "B.4.2: deep tree walk example" do
      records = %{
        "_dmarc.example.com" => [txt: "v=DMARC1; p=reject"],
        "_dmarc.signing.example.com" => [txt: "v=DMARC1; p=reject"]
      }

      result =
        evaluate("a@a.b.c.d.e.f.g.h.i.j.k.example.com", records, [dkim("signing.example.com")],
          spf: spf("example.com")
        )

      assert result.result == :pass
      assert result.organizational_domain == "example.com"
      assert result.record_domain == "example.com"
      assert result.aligned_by == [:dkim, :spf]
    end

    test "B.4.3: a PSD record with psd=y" do
      records = %{
        "_dmarc.bank.example" => [txt: "v=DMARC1; p=reject; psd=y"],
        "_dmarc.giant.bank.example" => [txt: "v=DMARC1; p=quarantine"]
      }

      result =
        evaluate("a@giant.bank.example", records, [dkim("mail.mega.bank.example")],
          spf: spf("mail.giant.bank.example")
        )

      assert result.result == :pass
      assert result.organizational_domain == "giant.bank.example"
      assert result.record_domain == "giant.bank.example"
      assert result.policy == :quarantine
      assert result.aligned_by == [:spf]

      result = evaluate("a@giant.bank.example", records, [dkim("mail.mega.bank.example")])
      assert result.result == :fail
      assert result.dkim_domain == "mail.mega.bank.example"
    end

    test "psd=n makes that domain the organizational domain" do
      records = %{
        "_dmarc.mail.example.com" => [txt: "v=DMARC1; p=reject; psd=n"],
        "_dmarc.example.com" => [txt: "v=DMARC1; p=none"]
      }

      assert %{organizational_domain: "mail.example.com", policy: :reject} =
               evaluate("a@a.mail.example.com", records, [])

      assert %{result: :fail} = evaluate("a@a.mail.example.com", records, [dkim("example.com")])
    end

    test "the walk for one domain is done once per call" do
      records = %{"_dmarc.example.com" => [txt: "v=DMARC1; p=reject"]}

      {result, queries} =
        capture_queries(fn ->
          evaluate("a@example.com", records, [dkim("a.example.com"), dkim("a.example.com")],
            spf: spf("a.example.com")
          )
        end)

      assert result.result == :pass
      assert Enum.count(queries, &(&1 == {"_dmarc.a.example.com", :txt})) == 1
    end
  end

  describe "alignment" do
    @records %{"_dmarc.example.com" => [txt: "v=DMARC1; p=reject"]}

    test "relaxed: a subdomain aligns" do
      assert %{result: :pass, aligned_by: [:dkim], dkim_domain: "mail.example.com"} =
               evaluate("a@example.com", @records, [dkim("mail.example.com")])
    end

    test "strict: only the same domain aligns" do
      records = %{"_dmarc.example.com" => [txt: "v=DMARC1; p=reject; adkim=s; aspf=s"]}

      assert %{result: :fail, reason: :not_aligned} =
               evaluate("a@example.com", records, [dkim("mail.example.com")],
                 spf: spf("mail.example.com")
               )

      assert %{result: :pass} = evaluate("a@example.com", records, [dkim("example.com")])
    end

    test "another domain does not align" do
      assert %{result: :fail, disposition: :reject} =
               evaluate("a@example.com", @records, [dkim("example.net")], spf: spf("example.net"))
    end

    test "a failed signature does not align" do
      assert %{result: :fail} = evaluate("a@example.com", @records, [dkim("example.com", :fail)])
    end

    test "SPF fail does not align" do
      assert %{result: :fail} =
               evaluate("a@example.com", @records, [], spf: spf("example.com", :fail))
    end

    test "a DNS failure on an aligned check is temperror" do
      assert %{result: :temperror, reason: :dns_error} =
               evaluate("a@example.com", @records, [dkim("example.com", :temperror)])

      assert %{result: :temperror} =
               evaluate("a@example.com", @records, [], spf: spf("example.com", :temperror))
    end

    test "a DKIM check stopped by the deadline gives :deadline" do
      timed_out = %DKIM.Result{result: :temperror, reason: :deadline, domain: "example.com"}

      assert %{result: :temperror, reason: :deadline} =
               evaluate("a@example.com", @records, [timed_out])
    end

    test "a pass wins over a temperror" do
      assert %{result: :pass} =
               evaluate("a@example.com", @records, [
                 dkim("example.com", :temperror),
                 dkim("example.com")
               ])
    end

    test "internationalized From domain (RFC 8616)" do
      records = %{"_dmarc.xn--mnchen-3ya.example" => [txt: "v=DMARC1; p=reject; adkim=s"]}

      result = evaluate("a@münchen.example", records, [dkim("xn--mnchen-3ya.example")])
      assert result.from_domain == "xn--mnchen-3ya.example"
      assert result.result == :pass
    end
  end

  describe "the policy that applies" do
    @records %{"_dmarc.example.com" => [txt: "v=DMARC1; p=reject; sp=quarantine; np=none"]}

    test "p at the From domain" do
      assert %{policy: :reject, disposition: :reject} = evaluate("a@example.com", @records, [])
    end

    test "sp for a subdomain that exists" do
      records = Map.put(@records, "sub.example.com", a: {192, 0, 2, 1})

      assert %{policy: :quarantine, disposition: :quarantine} =
               evaluate("a@sub.example.com", records, [])
    end

    test "np for a subdomain that does not exist" do
      assert %{policy: :none, disposition: :none} = evaluate("a@ghost.example.com", @records, [])
    end

    test "np falls back to sp, and sp to p" do
      records = %{"_dmarc.example.com" => [txt: "v=DMARC1; p=reject; sp=quarantine"]}
      assert %{policy: :quarantine} = evaluate("a@ghost.example.com", records, [])

      records = %{"_dmarc.example.com" => [txt: "v=DMARC1; p=reject"]}
      assert %{policy: :reject} = evaluate("a@ghost.example.com", records, [])
    end

    test "t=y steps the disposition down one level" do
      records = %{"_dmarc.example.com" => [txt: "v=DMARC1; p=reject; t=y"]}

      assert %{policy: :reject, testing?: true, disposition: :quarantine} =
               evaluate("a@example.com", records, [])

      records = %{"_dmarc.example.com" => [txt: "v=DMARC1; p=quarantine; t=y"]}
      assert %{disposition: :none} = evaluate("a@example.com", records, [])
    end

    test "a pass has no disposition" do
      assert %{result: :pass, disposition: :none} =
               evaluate("a@example.com", @records, [dkim("example.com")])
    end

    test "no valid p and a rua address: read as p=none" do
      records = %{"_dmarc.example.com" => [txt: "v=DMARC1; rua=mailto:d@example.com"]}

      assert %{result: :fail, policy: :none, disposition: :none, warnings: [:missing_policy]} =
               evaluate("a@example.com", records, [])
    end

    test "no valid p and no rua: DMARC does not apply" do
      records = %{"_dmarc.example.com" => [txt: "v=DMARC1; p=bounce"]}
      assert %{result: :none, reason: :invalid_record} = evaluate("a@example.com", records, [])
    end
  end

  describe "DNS failures" do
    test "a temporary failure in the walk is temperror" do
      assert %{result: :temperror, reason: :dns_error} =
               evaluate("a@example.com", %{"_dmarc.example.com" => :temperror}, [])
    end
  end

  describe "lookup/2" do
    test "returns the record, where it was found, and the organizational domain" do
      records = %{"_dmarc.example.com" => [txt: "v=DMARC1; p=reject"]}

      assert {:ok, %Record{domain: "example.com", p: :reject}, "example.com"} =
               DMARC.lookup("mail.example.com", static(records))

      assert {:error, :no_record} = DMARC.lookup("example.org", static(records))
      assert {:error, :invalid_domain} = DMARC.lookup("bad..domain", static(records))
    end
  end

  describe ":organizational_domain" do
    test "replaces the tree walk" do
      org = fn domain, _opts ->
        {:ok, domain |> String.split(".") |> Enum.take(-2) |> Enum.join(".")}
      end

      records = %{"_dmarc.example.com" => [txt: "v=DMARC1; p=reject"]}

      {result, queries} =
        capture_queries(fn ->
          evaluate("a@a.b.example.com", records, [dkim("x.example.com")],
            organizational_domain: org
          )
        end)

      assert result.result == :pass
      assert result.organizational_domain == "example.com"
      assert Enum.map(queries, &elem(&1, 0)) == ["_dmarc.a.b.example.com", "_dmarc.example.com"]
    end
  end
end
