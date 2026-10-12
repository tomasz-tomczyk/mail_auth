defmodule MailAuth.SPFTest do
  use ExUnit.Case, async: true

  import MailAuth.Test.Helpers

  alias MailAuth.SPF
  alias MailAuth.SPF.Macro

  describe "macros, the RFC 7208 section 7.4 examples" do
    @vars %{
      ?s => "strong-bad@email.example.com",
      ?l => "strong-bad",
      ?o => "email.example.com",
      ?d => "email.example.com",
      ?i => "192.0.2.3",
      ?v => "in-addr",
      ?h => "",
      ?p => "mx.example.org"
    }

    for {macro, expansion} <- [
          {"%{s}", "strong-bad@email.example.com"},
          {"%{o}", "email.example.com"},
          {"%{d}", "email.example.com"},
          {"%{d4}", "email.example.com"},
          {"%{d3}", "email.example.com"},
          {"%{d2}", "example.com"},
          {"%{d1}", "com"},
          {"%{dr}", "com.example.email"},
          {"%{d2r}", "example.email"},
          {"%{l}", "strong-bad"},
          {"%{l-}", "strong.bad"},
          {"%{lr}", "strong-bad"},
          {"%{lr-}", "bad.strong"},
          {"%{l1r-}", "strong"},
          {"%{ir}.%{v}._spf.%{d2}", "3.2.0.192.in-addr._spf.example.com"},
          {"%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"},
          {"%{lr-}.lp.%{ir}.%{v}._spf.%{d2}", "bad.strong.lp.3.2.0.192.in-addr._spf.example.com"},
          {"%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}", "3.2.0.192.in-addr.strong.lp._spf.example.com"},
          {"%{d2}.trusted-domains.example.net", "example.com.trusted-domains.example.net"},
          {"%{p1r}", "mx"},
          {"%%%_%-", "% %20"},
          {"%{S}", "strong-bad%40email.example.com"}
        ] do
      test macro do
        assert {:ok, parts} = Macro.parse(unquote(macro))
        assert Macro.expand(parts, @vars) == unquote(expansion)
      end
    end

    test "bad macros" do
      for bad <- ["%{x}", "%{d0}", "%", "%{d", "%a", "%{c}"],
          do: assert(Macro.parse(bad) == :error, bad)

      assert {:ok, _} = Macro.parse("%{c} is not allowed", exp: true)
    end
  end

  describe "check/4" do
    @records %{
      "example.com" => [
        txt: "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.example.net -all"
      ],
      "_spf.example.net" => [txt: "v=spf1 a:mx.example.net ~all"],
      "mx.example.net" => [a: {198, 51, 100, 7}]
    }

    defp check(ip, from, records \\ @records, opts \\ []),
      do: SPF.check(ip, from, "mx.sender.example", static(records, opts))

    test "pass, with the mechanism and the path through includes" do
      result = check("198.51.100.7", "a@example.com")
      assert result.result == :pass
      assert result.mechanism == "include:_spf.example.net"
      assert result.identity == :mailfrom
      assert result.ip == "198.51.100.7"
      assert [{"example.com", _}, {"_spf.example.net", _}] = result.trace
    end

    test "ip4 and ip6" do
      assert %{result: :pass, mechanism: "ip4:192.0.2.0/24"} =
               check({192, 0, 2, 99}, "a@example.com")

      assert %{result: :pass, mechanism: "ip6:2001:db8::/32"} =
               check("2001:db8::1", "a@example.com")

      assert %{result: :pass} = check("::ffff:192.0.2.1", "a@example.com")
    end

    test "fail with the exp= text" do
      records = %{
        "example.com" => [txt: "v=spf1 -all exp=why.example.com"],
        "why.example.com" => [txt: "%{i} is not one of %{d}'s servers"]
      }

      assert %{
               result: :fail,
               mechanism: "-all",
               explanation: "203.0.113.1 is not one of example.com's servers"
             } =
               check("203.0.113.1", "a@example.com", records)
    end

    test "a bounce checks the HELO name" do
      records = %{"mx.sender.example" => [txt: "v=spf1 ip4:203.0.113.1 -all"]}

      assert %{result: :pass, identity: :helo, mail_from: "postmaster@mx.sender.example"} =
               check("203.0.113.1", "", records)

      assert %{result: :pass, identity: :helo} = check("203.0.113.1", nil, records)
    end

    test "no record, and no valid domain" do
      assert %{result: :none, reason: :no_record} = check("203.0.113.1", "a@example.org")
      assert %{result: :none, reason: :invalid_domain} = check("203.0.113.1", "a@localhost")
      assert %{result: :none, reason: :invalid_ip} = check("not an ip", "a@example.com")
    end

    test "softfail and neutral" do
      assert %{result: :softfail, mechanism: "~all"} = check("203.0.113.1", "a@_spf.example.net")

      assert %{result: :neutral, reason: :no_match} =
               check("203.0.113.1", "a@x.example", %{"x.example" => [txt: "v=spf1 a"]})
    end

    test "too many lookups" do
      records =
        Map.new(0..11, fn i ->
          {"l#{i}.example", [txt: "v=spf1 include:l#{i + 1}.example -all"]}
        end)

      assert %{result: :permerror, reason: :too_many_lookups} =
               check("203.0.113.1", "a@l0.example", records)
    end

    test "too many void lookups" do
      records = %{"v.example" => [txt: "v=spf1 a:n1.example a:n2.example a:n3.example -all"]}

      assert %{result: :permerror, reason: :too_many_void_lookups} =
               check("203.0.113.1", "a@v.example", records)
    end

    test "record errors" do
      for {records, reason} <- [
            {%{"e.example" => [txt: "v=spf1 -all", txt: "v=spf1 +all"]}, :multiple_records},
            {%{"e.example" => [txt: "v=spf1 bogus:x -all"]}, :malformed_record},
            {%{"e.example" => [txt: "v=spf1 include:nothing.example -all"]}, :include_no_record},
            {%{"e.example" => [txt: "v=spf1 redirect=nothing.example"]}, :redirect_no_record},
            {%{
               "e.example" =>
                 [txt: "v=spf1 mx -all"] ++ for(i <- 1..11, do: {:mx, {i, "mx#{i}.example"}})
             }, :too_many_mx}
          ] do
        assert %{result: :permerror, reason: ^reason} =
                 check("203.0.113.1", "a@e.example", records)
      end
    end

    test "ptr works, with a warning" do
      records = %{
        "p.example" => [txt: "v=spf1 ptr -all"],
        "1.113.0.203.in-addr.arpa" => [ptr: "mail.p.example"],
        "mail.p.example" => [a: {203, 0, 113, 1}]
      }

      assert %{result: :pass, warnings: [:ptr_used]} =
               check("203.0.113.1", "a@p.example", records)
    end

    test "DNS failures and the deadline" do
      assert %{result: :temperror, reason: :dns_error} =
               check("203.0.113.1", "a@t.example", %{"t.example" => :temperror})

      assert %{result: :temperror, reason: :deadline} =
               check("203.0.113.1", "a@example.com", @records, deadline: 0)
    end
  end

  describe "received_spf/2" do
    test "writes the header" do
      result = SPF.check("198.51.100.7", "a@example.com", "mx.sender.example", static(@records))

      assert SPF.received_spf(result, receiver: "mx.example.org") ==
               "Received-SPF: pass (mx.example.org: domain of a@example.com designates 198.51.100.7 as permitted sender) " <>
                 "client-ip=198.51.100.7; envelope-from=\"a@example.com\"; helo=mx.sender.example; " <>
                 "receiver=mx.example.org; mechanism=\"include:_spf.example.net\"; identity=mailfrom;"
    end

    test "quotes values that need it, and names the problem" do
      result = %SPF.Result{
        result: :permerror,
        reason: :too_many_lookups,
        ip: "192.0.2.1",
        mail_from: "\"a b\"@example.com",
        identity: :mailfrom
      }

      assert SPF.received_spf(result) =~
               ~s(envelope-from="\\"a b\\"@example.com"; receiver=unknown; problem=too_many_lookups; identity=mailfrom;)
    end
  end
end
