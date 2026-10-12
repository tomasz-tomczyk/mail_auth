defmodule MailAuth.AuthenticationResultsTest do
  use ExUnit.Case, async: true
  doctest MailAuth.AuthenticationResults

  alias MailAuth.AuthenticationResults, as: AR
  alias MailAuth.AuthenticationResults.Method

  describe "parse/2, the RFC 8601 appendix B examples" do
    test "B.2: nothing done" do
      assert [%AR{authserv_id: "example.org", results: []}] = AR.parse("example.org 1; none")
    end

    test "B.3: SPF" do
      assert [%AR{authserv_id: "example.com", results: [m]}] =
               AR.parse("example.com;\r\n          spf=pass smtp.mailfrom=example.net")

      assert m == %Method{
               method: "spf",
               result: :pass,
               properties: %{"smtp.mailfrom" => "example.net"}
             }
    end

    test "B.4: SMTP AUTH and SPF, with comments" do
      value =
        "example.com;\r\n auth=pass (cram-md5) smtp.auth=sender@example.com;\r\n" <>
          " spf=pass smtp.mailfrom=example.com"

      assert [%AR{results: [auth, spf]}] = AR.parse(value)
      assert auth.method == "auth"
      assert auth.properties == %{"smtp.auth" => "sender@example.com"}
      assert spf.result == :pass
    end

    test "B.5: sender-id, hardfail and a version" do
      value =
        "example.com;\r\n sender-id=hardfail header.from=example.com;\r\n dkim/1=pass header.i=sender@example.com"

      assert [%AR{results: [sid, dkim]}] = AR.parse(value)
      assert sid.result == :hardfail
      assert dkim.version == "1"
      assert dkim.properties == %{"header.i" => "sender@example.com"}
    end

    test "B.6: several headers in a message" do
      raw =
        "Authentication-Results: example.com;\r\n" <>
          "    dkim=pass (good signature) header.d=mail-router.example.net;\r\n" <>
          "    dkim=fail (bad signature) header.d=newyork.example.com\r\n" <>
          "Authentication-Results: mail-router.example.net;\r\n" <>
          "    dkim=pass (good signature) header.d=newyork.example.com\r\n" <>
          "From: sender@newyork.example.com\r\n\r\nbody\r\n"

      assert [first, second] = AR.parse(raw, trusted: ["Example.COM"])
      assert first.trusted?
      refute second.trusted?
      assert Enum.map(first.results, & &1.result) == [:pass, :fail]
      assert second.authserv_id == "mail-router.example.net"
    end
  end

  describe "parse/2, headers seen in the wild" do
    test "a Gmail header" do
      value =
        "mx.google.com;\r\n" <>
          "       dkim=pass header.i=@example.com header.s=s1 header.b=Ab1cD2eF;\r\n" <>
          "       spf=pass (google.com: domain of a@example.com designates 192.0.2.1 as permitted sender) smtp.mailfrom=a@example.com;\r\n" <>
          "       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com"

      assert [%AR{authserv_id: "mx.google.com", trusted?: true, warnings: [], results: [d, s, m]}] =
               AR.parse("Authentication-Results: " <> value, trusted: ["mx.google.com"])

      assert d.properties == %{
               "header.i" => "@example.com",
               "header.s" => "s1",
               "header.b" => "Ab1cD2eF"
             }

      assert s.properties == %{"smtp.mailfrom" => "a@example.com"}
      assert m.method == "dmarc"
      assert m.properties == %{"header.from" => "example.com"}
    end

    test "an Outlook header without an authserv-id is never trusted" do
      value =
        "spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=example.com; dkim=pass (signature was verified)\r\n" <>
          " header.d=example.com;dmarc=pass action=none header.from=example.com;compauth=pass reason=100"

      assert [
               %AR{
                 authserv_id: nil,
                 trusted?: false,
                 warnings: [:no_authserv_id],
                 results: results
               }
             ] =
               AR.parse(value, trusted: ["spf=pass"])

      assert Enum.map(results, & &1.method) == ["spf", "dkim", "dmarc", "compauth"]
      assert List.last(results).reason == "100"

      assert Enum.at(results, 2).properties == %{
               "action" => "none",
               "header.from" => "example.com"
             }
    end

    test "base64 padding in a value" do
      assert [%AR{results: [m]}] = AR.parse("example.com; dkim=pass header.b=abc= header.s=x")
      assert m.properties == %{"header.b" => "abc=", "header.s" => "x"}
    end

    test "quoted values and reasons" do
      assert [%AR{authserv_id: "example.com", results: [m]}] =
               AR.parse(
                 ~s("example.com"; dkim=fail reason="body hash; mismatch" header.d=example.com)
               )

      assert m.reason == "body hash; mismatch"
    end

    test "unknown results are kept as text" do
      assert [%AR{results: [%Method{method: "x-new", result: "maybe"}]}] =
               AR.parse("example.com; x-new=maybe")
    end

    test "broken input gives what could be read" do
      assert [
               %AR{
                 authserv_id: "example.com",
                 warnings: [:malformed],
                 results: [%{method: "spf"}]
               }
             ] =
               AR.parse("example.com; spf=pass; dkim (unclosed")
    end
  end

  describe "format/2" do
    test "every method, with properties and reasons" do
      result = %MailAuth.Result{
        dkim: [
          %MailAuth.DKIM.Result{
            result: :pass,
            domain: "example.com",
            selector: "s1",
            identity: "@example.com",
            algorithm: :rsa_sha256
          },
          %MailAuth.DKIM.Result{
            result: :fail,
            reason: :body_hash_mismatch,
            domain: "example.net",
            selector: "x"
          }
        ],
        spf: %MailAuth.SPF.Result{
          result: :pass,
          mail_from: "a@example.com",
          identity: :mailfrom,
          ip: "192.0.2.1"
        },
        dmarc: %MailAuth.DMARC.Result{
          result: :pass,
          from_domain: "example.com",
          policy: :reject,
          disposition: :none
        }
      }

      header = AR.format(result, "mx.example.org")

      assert header ==
               "Authentication-Results: mx.example.org;\r\n" <>
                 " dkim=pass header.d=example.com header.i=@example.com header.s=s1 header.a=rsa-sha256;\r\n" <>
                 " dkim=fail reason=body_hash_mismatch header.d=example.net header.s=x;\r\n" <>
                 " spf=pass (192.0.2.1) smtp.mailfrom=a@example.com;\r\n" <>
                 " dmarc=pass (p=reject dis=none) header.from=example.com policy.dmarc=reject"

      [parsed] = AR.parse(header, trusted: ["mx.example.org"])
      assert parsed.trusted?

      assert Enum.map(parsed.results, &{&1.method, &1.result}) ==
               [{"dkim", :pass}, {"dkim", :fail}, {"spf", :pass}, {"dmarc", :pass}]

      assert Enum.at(parsed.results, 1).reason == "body_hash_mismatch"
    end

    test "a bounce uses smtp.helo" do
      result = %MailAuth.Result{
        spf: %MailAuth.SPF.Result{
          result: :none,
          reason: :no_record,
          identity: :helo,
          helo: "mx.example.com"
        }
      }

      assert AR.format(result, "mx") ==
               "Authentication-Results: mx;\r\n spf=none reason=no_record smtp.helo=mx.example.com"
    end
  end
end
