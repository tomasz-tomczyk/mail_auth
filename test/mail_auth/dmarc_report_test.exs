defmodule MailAuth.DMARC.ReportTest do
  use ExUnit.Case, async: true

  alias MailAuth.DMARC.Report

  @xml File.read!("test/fixtures/dmarc/rfc9990-example.xml")

  test "the RFC 9990 example" do
    assert {:ok, report} = Report.parse(@xml)
    assert report.version == "1.0"
    assert report.metadata.org_name == "Sample Reporter"
    assert report.metadata.report_id == "3v98abbp8ya9n3va8yr8oa3ya"
    assert report.metadata.begin == DateTime.from_unix!(302_832_000)
    assert report.metadata.end == DateTime.from_unix!(302_918_399)
    assert report.policy_published.domain == "example.com"
    assert report.policy_published.p == "quarantine"
    assert report.policy_published.discovery_method == "treewalk"

    assert [record] = report.records
    assert record.source_ip == "192.0.2.123"
    assert record.count == 123
    assert {record.disposition, record.dkim, record.spf} == {"pass", "pass", "fail"}
    assert record.header_from == "example.com"

    assert [%{domain: "example.com", selector: "abc123", result: "pass"}] =
             record.auth_results.dkim

    assert [%{domain: "example.com", result: "fail"}] = record.auth_results.spf
  end

  test "gzip and zip" do
    assert {:ok, %Report{records: [_]}} = Report.parse(:zlib.gzip(@xml))

    {:ok, {_, zip}} = :zip.create(~c"report.zip", [{~c"report.xml", @xml}], [:memory])
    assert {:ok, %Report{records: [_]}} = Report.parse(zip)
  end

  test "a report without a namespace, as RFC 7489 senders write them" do
    xml = String.replace(@xml, ~s( xmlns="urn:ietf:params:xml:ns:dmarc-2.0"), "")
    assert {:ok, %Report{policy_published: %{domain: "example.com"}}} = Report.parse(xml)
  end

  test "bad input" do
    assert {:error, :invalid_xml} = Report.parse("<feedback><unclosed></feedback>")
    assert {:error, :not_a_report} = Report.parse("<html></html>")
    assert {:error, :invalid_gzip} = Report.parse(<<0x1F, 0x8B, 1, 2, 3>>)
    assert {:error, :invalid_zip} = Report.parse(<<"PK", 3, 4, 1, 2, 3>>)
  end

  test "no DTD, so no entity expansion" do
    xml =
      ~s(<?xml version="1.0"?><!DOCTYPE feedback [<!ENTITY a "aaaa">]><feedback>&a;</feedback>)

    assert {:error, :doctype_not_allowed} = Report.parse(xml)
  end

  test "a zip that lies about its size is still capped" do
    big = :binary.copy(<<"<a/>">>, 13 * 1024 * 1024 + 1)
    {:ok, {_, zip}} = :zip.create(~c"r.zip", [{~c"r.xml", big}], [:memory])

    # Patch the uncompressed size, in the local header and the central
    # directory, to claim 1 KB.
    lied = :binary.replace(zip, <<byte_size(big)::little-32>>, <<1024::little-32>>, [:global])
    assert lied != zip
    assert {:error, :too_large} = Report.parse(lied)
  end

  test "a stored zip entry" do
    {:ok, {_, zip}} = :zip.create(~c"r.zip", [{~c"r.xml", @xml}], [:memory, {:compress, []}])
    assert {:ok, %Report{records: [_]}} = Report.parse(zip)
  end

  test "too large once uncompressed" do
    gzip = :zlib.gzip(:binary.copy(<<"<a/>">>, 13 * 1024 * 1024 + 1))
    assert byte_size(gzip) < 1_000_000
    assert {:error, :too_large} = Report.parse(gzip)
  end
end
