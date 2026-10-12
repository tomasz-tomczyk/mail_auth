defmodule MailAuth.DKIMVectorsTest do
  # Known signed messages: RFC 6376, RFC 8463, and messages signed with their keys.
  use ExUnit.Case, async: true

  alias MailAuth.DKIM
  alias MailAuth.Test.DKIMFixtures, as: F

  @opts [resolver: MailAuth.Resolver.Static, records: F.records(), now: 424_242]

  test "an unsigned message has no results" do
    assert DKIM.verify(F.unsigned_mail_string(), @opts) == []
  end

  test "RFC 6376 example, simple/simple" do
    assert [result] = DKIM.verify(F.verified_mail_string(), @opts)
    assert result.result == :pass
    assert result.domain == "example.com"
    assert result.identity == "joe@football.example.com"
    assert result.signed_headers == ~w(received from to subject date message-id)
    assert result.algorithm == :rsa_sha256
    assert result.key_bits == 1024
    assert result.canonicalization == {:simple, :simple}
  end

  test "a key published as a bare RSAPublicKey" do
    assert [result] = DKIM.verify(F.verified_raw_rsa_mail_string(), @opts)
    assert result.result == :pass
    assert result.signed_at == DateTime.from_unix!(1_615_825_284)
  end

  test "Ed25519 and RSA signatures on one message (RFC 8463)" do
    assert [ed, rsa] = DKIM.verify(F.verified_ed25519_mail_string(), @opts)
    assert ed.result == :pass
    assert ed.algorithm == :ed25519_sha256
    assert ed.domain == "football.example.com"
    assert ed.identity == "@football.example.com"
    assert ed.signed_headers == ~w(from to subject date message-id from subject date)
    assert ed.signed_at == DateTime.from_unix!(1_528_637_909)
    assert ed.warnings == []
    assert rsa.result == :pass
  end

  test "signatures past max_signatures are :none" do
    results = DKIM.verify(F.too_many_signatures_mail_string(), [max_signatures: 2] ++ @opts)

    assert [%{result: :pass}, %{result: :pass}, %{result: :none, reason: :too_many_signatures}] =
             results
  end

  test "sign with simple/simple and the test keys, then verify" do
    message =
      "From: Joe SixPack <joe@football.example.com>\r\n" <>
        "To: Suzie Q <suzie@shopping.example.net>\r\n" <>
        "Subject: Is dinner ready?\r\n" <>
        "Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n" <>
        "Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n" <>
        "\r\nHi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe."

    for {key, domain, selector} <- [
          {F.rsa_private_key_pem(), "example.org", "brisbane"},
          {{:ed25519, F.ed25519_seed()}, "football.example.com", "brisbane"}
        ] do
      {:ok, signed} =
        DKIM.sign(message,
          domain: domain,
          selector: selector,
          private_key: key,
          canonicalization: {:simple, :simple},
          headers: ~w(From To Subject Date Message-ID),
          oversign: [],
          now: 424_242
        )

      assert [%{result: :pass}] = DKIM.verify(signed, @opts)
    end
  end
end
