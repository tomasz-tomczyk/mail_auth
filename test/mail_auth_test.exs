defmodule MailAuthTest do
  use ExUnit.Case, async: true

  import MailAuth.Test.Helpers

  alias MailAuth.Result

  @records Map.merge(key_record("example.com"), %{
             "_dmarc.example.com" => [txt: "v=DMARC1; p=reject"],
             "example.com" => [txt: "v=spf1 ip4:192.0.2.0/24 -all"]
           })

  describe "mail read over IMAP: no client IP" do
    test "a signed message passes DMARC" do
      result = MailAuth.authenticate(sign(message(), "example.com"), static(@records))

      assert Result.dmarc_pass?(result)
      assert result.from_domain == "example.com"
      assert [%{result: :pass}] = result.dkim
      assert %{result: :none, reason: :no_client_ip} = result.spf
      assert %{result: :pass, aligned_by: [:dkim], policy: :reject} = result.dmarc
    end

    test "a signature from another domain does not" do
      records = Map.merge(@records, key_record("example.net"))
      result = MailAuth.authenticate(sign(message(), "example.net"), static(records))

      refute Result.dmarc_pass?(result)
      assert [%{result: :pass, domain: "example.net"}] = result.dkim
      assert %{result: :fail, reason: :not_aligned, disposition: :reject} = result.dmarc
    end

    test "an unsigned message" do
      result = MailAuth.authenticate(message(), static(@records))
      refute Result.dmarc_pass?(result)
      assert result.dkim == []
      assert result.dmarc.result == :fail
    end

    test "a forged Authentication-Results header changes nothing" do
      raw =
        "Authentication-Results: mx.google.com; dkim=pass header.d=example.com; dmarc=pass\r\n" <>
          message()

      refute raw |> MailAuth.authenticate(static(@records)) |> Result.dmarc_pass?()
    end
  end

  describe "an SMTP server: with the client IP" do
    test "SPF alone can pass DMARC" do
      result =
        MailAuth.authenticate(
          message(),
          static(@records,
            ip: "192.0.2.10",
            mail_from: "bounce@example.com",
            helo: "mx.example.com"
          )
        )

      assert Result.dmarc_pass?(result)
      assert %{result: :pass, domain: "example.com"} = result.spf
      assert result.dmarc.aligned_by == [:spf]

      header = MailAuth.AuthenticationResults.format(result, "mx.example.org")
      assert header =~ "spf=pass"
      assert header =~ "dmarc=pass"
    end
  end

  test "dmarc: false skips DMARC" do
    assert %{dmarc: nil} = MailAuth.authenticate(message(), static(@records, dmarc: false))
  end

  test "headers too large" do
    raw = String.duplicate("X-A: b\r\n", 1001) <> "\r\nbody"
    result = MailAuth.authenticate(raw, static(@records))
    assert %{result: :permerror, reason: :headers_too_large} = result.dmarc
    assert [%{reason: :headers_too_large}] = result.dkim
  end

  test "the deadline covers the whole call" do
    defmodule Slow do
      @behaviour MailAuth.Resolver
      def lookup(name, type, opts) do
        Process.sleep(60)
        MailAuth.Resolver.Static.lookup(name, type, opts)
      end
    end

    raw = sign(message(), "example.com")

    {time, result} =
      :timer.tc(fn ->
        MailAuth.authenticate(raw, resolver: Slow, records: @records, deadline: 100)
      end)

    assert div(time, 1000) < 400
    assert [%{result: :pass}] = result.dkim
    assert %{result: :temperror, reason: :deadline} = result.dmarc
  end

  test "telemetry spans, without message content" do
    ref = make_ref()
    parent = self()

    events = [
      [:mail_auth, :authenticate, :stop],
      [:mail_auth, :dkim, :verify, :stop],
      [:mail_auth, :dmarc, :stop],
      [:mail_auth, :spf, :stop],
      [:mail_auth, :dns, :lookup, :stop]
    ]

    :telemetry.attach_many(
      {__MODULE__, ref},
      events,
      fn event, measurements, meta, _ ->
        send(parent, {ref, event, measurements, meta})
      end,
      nil
    )

    MailAuth.authenticate(
      sign(message(), "example.com"),
      static(@records, ip: "192.0.2.10", mail_from: "a@example.com")
    )

    :telemetry.detach({__MODULE__, ref})

    assert_received {^ref, [:mail_auth, :authenticate, :stop], %{duration: _},
                     %{dkim: [:pass], spf: :pass, dmarc: :pass}}

    assert_received {^ref, [:mail_auth, :dkim, :verify, :stop], _, %{results: [:pass]}}
    assert_received {^ref, [:mail_auth, :dmarc, :stop], _, %{result: :pass}}
    assert_received {^ref, [:mail_auth, :spf, :stop], _, %{result: :pass}}
    assert_received {^ref, [:mail_auth, :dns, :lookup, :stop], _, %{name: _, type: _, result: _}}
  end
end
