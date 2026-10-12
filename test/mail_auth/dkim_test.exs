defmodule MailAuth.DKIMTest do
  use ExUnit.Case, async: true

  import MailAuth.Test.Helpers

  alias MailAuth.DKIM
  alias MailAuth.DKIM.Canonical
  alias MailAuth.Test.DKIMFixtures

  @now 1_700_000_000
  @records key_record("example.com")

  defp verify(raw, records \\ @records, opts \\ []),
    do: DKIM.verify(raw, static(records, Keyword.merge([now: @now], opts)))

  defp signed(opts \\ []), do: sign(message(), "example.com", Keyword.merge([now: @now], opts))

  defp one(raw, records \\ @records, opts \\ []) do
    [result] = verify(raw, records, opts)
    result
  end

  describe "a good signature" do
    test "passes, with every field filled in" do
      result = one(signed(identity: "joe@example.com", expires_in: 3600))

      assert result.result == :pass
      assert result.reason == nil
      assert result.domain == "example.com"
      assert result.selector == "s1"
      assert result.identity == "joe@example.com"
      assert result.algorithm == :rsa_sha256
      assert result.key_bits == 1024
      assert result.canonicalization == {:relaxed, :relaxed}
      assert result.signed_at == DateTime.from_unix!(@now)
      assert result.expires_at == DateTime.from_unix!(@now + 3600)
      assert result.body_length == nil
      refute result.testing?
      assert result.warnings == []

      assert result.signed_headers ==
               ~w(from from to to subject subject date date message-id)
    end

    test "Ed25519" do
      %{private_key: pem, dns_record: txt} = DKIM.generate_key(:ed25519)
      raw = sign(message(), "example.com", private_key: pem, selector: "ed", now: @now)
      result = one(raw, %{"ed._domainkey.example.com" => [txt: txt]})
      assert result.result == :pass
      assert result.algorithm == :ed25519_sha256
      assert result.key_bits == 256
    end

    test "a message with bare LF line endings" do
      raw = signed() |> String.replace("\r\n", "\n")
      assert %{result: :pass} = one(raw)
    end

    test "a header re-folded in transit still passes under relaxed" do
      raw =
        String.replace(signed(), "Subject: Is dinner ready?", "Subject: Is dinner\r\n   ready?")

      assert %{result: :pass} = one(raw)

      raw = signed(canonicalization: {:simple, :simple})
      raw = String.replace(raw, "Subject: Is dinner ready?", "Subject: Is dinner\r\n   ready?")
      assert %{result: :fail, reason: :signature_mismatch} = one(raw)
    end

    test "trailing empty lines added in transit still pass" do
      assert %{result: :pass} = one(signed() <> "\r\n\r\n")
    end

    test "several signatures at once" do
      %{private_key: ed_pem, dns_record: ed_txt} = DKIM.generate_key(:ed25519)

      {:ok, raw} =
        DKIM.sign(message(), [
          [
            domain: "example.com",
            selector: "s1",
            private_key: DKIMFixtures.rsa_private_key_pem()
          ],
          [domain: "example.com", selector: "ed", private_key: ed_pem]
        ])

      records = Map.put(@records, "ed._domainkey.example.com", txt: ed_txt)

      assert [%{selector: "s1", result: :pass}, %{selector: "ed", result: :pass}] =
               verify(raw, records)
    end

    test "an internationalized signing domain (RFC 8616)" do
      # d= is hashed as written, in U-labels, and looked up in A-labels.
      raw = message("joe@münchen.example")
      {:ok, msg} = MailAuth.Message.parse(raw)
      body = Canonical.body(msg.body, :relaxed)

      unsigned =
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=münchen.example; s=s1;\r\n" <>
          " h=from:subject; bh=#{Base.encode64(:crypto.hash(:sha256, body))};\r\n b="

      headers =
        for {name, raw} <- msg.headers,
            name in ["from", "subject"],
            do: Canonical.header(raw, :relaxed)

      sig_header =
        unsigned
        |> Kernel.<>("\r\n")
        |> Canonical.header(:relaxed)
        |> String.trim_trailing("\r\n")

      data = IO.iodata_to_binary([headers, sig_header])
      {:ok, {:rsa, key}} = MailAuth.DKIM.Key.private_key(DKIMFixtures.rsa_private_key_pem())
      signature = :public_key.sign(data, :sha256, key) |> Base.encode64()

      result = one(unsigned <> signature <> "\r\n" <> raw, key_record("xn--mnchen-3ya.example"))
      assert result.result == :pass
      assert result.domain == "xn--mnchen-3ya.example"
      assert result.identity == "@xn--mnchen-3ya.example"
    end

    test "an unsigned message has no results" do
      assert verify(message()) == []
    end
  end

  describe "changed after signing" do
    test "one byte of the body" do
      raw = String.replace(signed(), "hungry", "Hungry")
      assert %{result: :fail, reason: :body_hash_mismatch} = one(raw)
    end

    test "a signed header" do
      raw = String.replace(signed(), "Subject: Is dinner ready?", "Subject: Is lunch ready?")
      assert %{result: :fail, reason: :signature_mismatch} = one(raw)
    end

    test "a second From: added" do
      raw = String.replace(signed(), "From: Joe", "From: Evil <evil@example.org>\r\nFrom: Joe")
      assert %{result: :fail, reason: :signature_mismatch} = one(raw)
    end

    test "an unsigned header added is fine" do
      raw = String.replace(signed(), "From: Joe", "X-Spam: no\r\nFrom: Joe")
      assert %{result: :pass} = one(raw)
    end
  end

  describe "reasons" do
    defp tamper(from, to, opts \\ []), do: String.replace(signed(opts), from, to, global: false)

    test ":malformed_signature" do
      assert %{result: :permerror, reason: :malformed_signature} =
               one(tamper("v=1;", "v=1; broken;"))

      assert %{result: :permerror, reason: :malformed_signature} =
               one(tamper("v=1;", "v=1; t=soon;"))

      assert %{result: :permerror, reason: :malformed_signature} = one(tamper("bh=", "bh=!!"))

      assert %{result: :permerror, reason: :malformed_signature} =
               one(tamper("v=1;", "v=1; v=1;"))
    end

    test ":missing_tag" do
      assert %{result: :permerror, reason: :missing_tag} = one(tamper("s=s1;", ""))
    end

    test ":unsupported_version" do
      assert %{result: :permerror, reason: :unsupported_version} = one(tamper("v=1;", "v=2;"))
    end

    test ":unsupported_algorithm" do
      assert %{result: :permerror, reason: :unsupported_algorithm, algorithm: nil} =
               one(tamper("a=rsa-sha256", "a=rsa-sha512"))
    end

    test ":unsupported_canonicalization" do
      assert %{result: :permerror, reason: :unsupported_canonicalization} =
               one(tamper("c=relaxed/relaxed", "c=relaxed/loose"))
    end

    test ":from_not_signed" do
      raw = sign(message(), "example.com", headers: ["From", "Subject"], oversign: [], now: @now)
      raw = String.replace(raw, "h=From:Subject", "h=Subject")
      assert %{result: :permerror, reason: :from_not_signed} = one(raw)
    end

    test ":domain_mismatch" do
      raw = signed(identity: "joe@example.org")
      assert %{result: :permerror, reason: :domain_mismatch} = one(raw)
    end

    test ":expired and :invalid_expiry" do
      raw = signed(expires_in: 60)
      assert %{result: :pass} = one(raw, @records, now: @now + 59)
      assert %{result: :permerror, reason: :expired} = one(raw, @records, now: @now + 61)

      raw = tamper("t=#{@now}", "t=#{@now}; x=#{@now - 1}")
      assert %{result: :permerror, reason: :invalid_expiry} = one(raw)
    end

    test ":unsupported_query_method" do
      assert %{result: :permerror, reason: :unsupported_query_method} =
               one(tamper("v=1;", "v=1; q=dns/udp;"))

      assert %{result: :fail} = one(tamper("v=1;", "v=1; q=dns/txt;"))
    end

    test ":weak_algorithm, unless allow_sha1" do
      raw = File.read!("test/fixtures/dkim/rsa-sha1.eml")
      assert %{result: :permerror, reason: :weak_algorithm, algorithm: :rsa_sha1} = one(raw)

      assert %{result: :pass, warnings: warnings} = one(raw, @records, allow_sha1: true)
      assert :weak_algorithm in warnings
    end

    test ":no_key" do
      assert %{result: :permerror, reason: :no_key} = one(signed(), %{})

      assert %{result: :permerror, reason: :no_key} =
               one(signed(), %{"s1._domainkey.example.com" => [a: {1, 2, 3, 4}]})
    end

    test ":key_revoked" do
      records = %{"s1._domainkey.example.com" => [txt: "v=DKIM1; p="]}
      assert %{result: :permerror, reason: :key_revoked} = one(signed(), records)
    end

    test ":malformed_key" do
      for txt <- [
            "v=DKIM1; p=!!!",
            "v=DKIM1; k=rsa",
            "p=MIGf; v=DKIM1",
            "v=DKIM2; p=MIGf",
            "v=DKIM1; p=AAAA"
          ] do
        records = %{"s1._domainkey.example.com" => [txt: txt]}
        assert %{result: :permerror, reason: :malformed_key} = one(signed(), records), txt
      end
    end

    test ":multiple_keys" do
      records = %{
        "s1._domainkey.example.com" => [
          txt: DKIMFixtures.dns_public_key(),
          txt: DKIMFixtures.dns_public_key()
        ]
      }

      assert %{result: :permerror, reason: :multiple_keys} = one(signed(), records)

      # One key and some unrelated text is fine.
      records = %{
        "s1._domainkey.example.com" => [txt: DKIMFixtures.dns_public_key(), txt: "hello"]
      }

      assert %{result: :pass} = one(signed(), records)
    end

    test ":unsupported_key_type and :key_algorithm_mismatch" do
      records = %{"s1._domainkey.example.com" => [txt: "v=DKIM1; k=dsa; p=AAAA"]}
      assert %{result: :permerror, reason: :unsupported_key_type} = one(signed(), records)

      %{dns_record: ed_txt} = DKIM.generate_key(:ed25519)
      records = %{"s1._domainkey.example.com" => [txt: ed_txt]}
      assert %{result: :permerror, reason: :key_algorithm_mismatch} = one(signed(), records)
    end

    test ":key_hash_mismatch" do
      records = %{
        "s1._domainkey.example.com" => [txt: DKIMFixtures.dns_public_key() <> "; h=sha1"]
      }

      assert %{result: :permerror, reason: :key_hash_mismatch} = one(signed(), records)

      records = %{
        "s1._domainkey.example.com" => [txt: DKIMFixtures.dns_public_key() <> "; h=sha1:sha256"]
      }

      assert %{result: :pass} = one(signed(), records)
    end

    test ":key_service_mismatch" do
      records = %{
        "s1._domainkey.example.com" => [txt: DKIMFixtures.dns_public_key() <> "; s=other"]
      }

      assert %{result: :permerror, reason: :key_service_mismatch} = one(signed(), records)

      for s <- ["email", "*", "other:email"] do
        records = %{
          "s1._domainkey.example.com" => [txt: DKIMFixtures.dns_public_key() <> "; s=#{s}"]
        }

        assert %{result: :pass} = one(signed(), records)
      end
    end

    test ":strict_identity_mismatch" do
      records = %{"s1._domainkey.example.com" => [txt: DKIMFixtures.dns_public_key() <> "; t=s"]}

      assert %{result: :permerror, reason: :strict_identity_mismatch} =
               one(signed(identity: "joe@mail.example.com"), records)

      assert %{result: :pass} = one(signed(identity: "joe@example.com"), records)
    end

    test "testing? for t=y" do
      records = %{"s1._domainkey.example.com" => [txt: DKIMFixtures.dns_public_key() <> "; t=y"]}
      assert %{result: :pass, testing?: true} = one(signed(), records)
    end

    test ":key_too_small" do
      assert %{result: :permerror, reason: :key_too_small, key_bits: 1024} =
               one(signed(), @records, min_key_bits: 2048)
    end

    test ":key_too_large" do
      n = Integer.pow(2, 4100) + 1

      {:SubjectPublicKeyInfo, der, _} =
        :public_key.pem_entry_encode(:SubjectPublicKeyInfo, {:RSAPublicKey, n, 65_537})

      records = %{"s1._domainkey.example.com" => [txt: "v=DKIM1; p=" <> Base.encode64(der)]}
      assert %{result: :permerror, reason: :key_too_large} = one(signed(), records)
    end

    test ":body_length_exceeds, and the :body_length_limit warning" do
      raw = signed(body_length: true)
      assert %{result: :pass, warnings: [:body_length_limit], body_length: l} = one(raw)
      assert l > 0

      # Text added after the signed length still passes, which is why l= is unsafe.
      assert %{result: :pass} = one(raw <> "Click here: https://evil.example\r\n")

      raw = String.replace(raw, "l=#{l}", "l=#{l + 100}")
      assert %{result: :permerror, reason: :body_length_exceeds} = one(raw)
    end

    test ":dns_error and :deadline" do
      assert %{result: :temperror, reason: :dns_error} =
               one(signed(), %{"s1._domainkey.example.com" => :temperror})

      assert %{result: :temperror, reason: :deadline} = one(signed(), @records, deadline: 0)
    end

    test ":too_many_signatures" do
      raw =
        signed()
        |> then(&sign(&1, "example.com", now: @now))
        |> then(&sign(&1, "example.com", now: @now))

      assert [
               %{result: :pass},
               %{result: :none, reason: :too_many_signatures, domain: "example.com"},
               _
             ] =
               verify(raw, @records, max_signatures: 1)
    end

    test ":headers_too_large" do
      raw = String.duplicate("X-A: b\r\n", 1001) <> "\r\nbody"
      assert [%{result: :permerror, reason: :headers_too_large}] = verify(raw)
    end
  end

  describe "warnings" do
    test "headers not signed, From not oversigned" do
      raw = sign(message(), "example.com", headers: ["From", "Date"], oversign: [], now: @now)
      assert %{result: :pass, warnings: warnings} = one(raw)
      assert warnings == [:from_not_oversigned, :subject_not_signed, :to_not_signed]
    end
  end

  describe "sign/2" do
    test "checks its options" do
      key = DKIMFixtures.rsa_private_key_pem()
      base = [domain: "example.com", selector: "s1", private_key: key]

      assert {:error, :missing_domain} = DKIM.sign(message(), Keyword.delete(base, :domain))
      assert {:error, :missing_selector} = DKIM.sign(message(), Keyword.delete(base, :selector))

      assert {:error, :missing_private_key} =
               DKIM.sign(message(), Keyword.delete(base, :private_key))

      assert {:error, :invalid_private_key} =
               DKIM.sign(message(), Keyword.put(base, :private_key, "nope"))

      assert {:error, :key_algorithm_mismatch} =
               DKIM.sign(message(), Keyword.put(base, :algorithm, :ed25519_sha256))

      assert {:error, :unsupported_algorithm} =
               DKIM.sign(message(), Keyword.put(base, :algorithm, :rsa_sha1))

      assert {:error, :unsupported_canonicalization} =
               DKIM.sign(message(), Keyword.put(base, :canonicalization, :loose))

      assert {:error, :from_not_signed} =
               DKIM.sign(message(), Keyword.put(base, :headers, ["To"]))
    end

    test "keeps LF line endings when the message uses them" do
      raw = message() |> String.replace("\r\n", "\n")

      {:ok, signed} =
        DKIM.sign(raw,
          domain: "example.com",
          selector: "s1",
          private_key: DKIMFixtures.rsa_private_key_pem()
        )

      refute String.contains?(signed, "\r")
      assert %{result: :pass} = one(signed)
    end

    test "folds lines to 78 characters" do
      for line <- String.split(signed(), "\r\n"), do: assert(byte_size(line) <= 78, line)
    end

    test "signature_header/2 gives the header alone" do
      {:ok, header} =
        DKIM.signature_header(message(),
          domain: "example.com",
          selector: "s1",
          private_key: DKIMFixtures.rsa_private_key_pem()
        )

      assert String.starts_with?(
               header,
               "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;"
             )

      refute String.ends_with?(header, "\r\n")
      assert %{result: :pass} = one(header <> "\r\n" <> message())
    end
  end

  describe "generate_key/2" do
    test "RSA" do
      key = DKIM.generate_key(:rsa, selector: "s1", domain: "Example.com")
      assert key.dns_name == "s1._domainkey.example.com"
      assert String.starts_with?(key.dns_record, "v=DKIM1; k=rsa; p=")
      assert {:ok, %{type: :rsa, bits: 2048}} = MailAuth.DKIM.Key.parse(key.dns_record)
      assert String.contains?(key.private_key, "BEGIN RSA PRIVATE KEY")
    end

    test "Ed25519" do
      key = DKIM.generate_key(:ed25519)
      assert {:ok, %{type: :ed25519}} = MailAuth.DKIM.Key.parse(key.dns_record)
      assert String.contains?(key.private_key, "BEGIN PRIVATE KEY")
      refute Map.has_key?(key, :dns_name)
    end
  end
end
