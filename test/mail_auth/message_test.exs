defmodule MailAuth.MessageTest do
  use ExUnit.Case, async: true

  alias MailAuth.Message

  test "splits headers and body, keeping folding" do
    raw = "From: a@b.c\r\nSubject: one\r\n two\r\n\r\nbody\r\n\r\n"
    assert {:ok, msg} = Message.parse(raw)
    assert msg.headers == [{"from", "From: a@b.c\r\n"}, {"subject", "Subject: one\r\n two\r\n"}]
    assert msg.body == "body\r\n\r\n"
  end

  test "reads bare LF in headers as CRLF and keeps the body as stored" do
    # DKIM canonicalization reads a bare LF in the body as CRLF.
    assert {:ok, %{headers: [{"from", "From: a@b.c\r\n"}], body: "x\ny\r\nz\r", bare_lf: true}} =
             Message.parse("From: a@b.c\n\nx\ny\r\nz\r")
  end

  test "bare_lf is set by any bare LF in the header block" do
    assert {:ok, %{bare_lf: false}} = Message.parse("From: a@b.c\r\n\r\nx\ny\n")
    assert {:ok, %{bare_lf: true}} = Message.parse("From: a@b.c\nTo: d@e.f\r\n\r\nx")
    assert {:ok, %{bare_lf: true}} = Message.parse("From: a@b.c\r\nSubject: one\n two\r\n\r\n")
    assert {:ok, %{bare_lf: true}} = Message.parse("From: a@b.c\r\n\nx")
    assert {:ok, %{bare_lf: true}} = Message.parse("From: a@b.c\n")
    assert {:ok, %{bare_lf: false}} = Message.parse("From: a@b.c")
  end

  test "finds the empty line after the headers whatever the line endings" do
    for raw <- ["A: b\n\nbody", "A: b\r\n\nbody", "A: b\n\r\nbody", "A: b\r\n\r\nbody"] do
      assert {:ok, %{headers: [{"a", "A: b\r\n"}], body: "body"}} = Message.parse(raw)
    end

    # A line holding only CR CR is not empty.
    assert {:ok, %{headers: [{"a", "A: b\r\n"}, {"", "\r\r\n"}], body: "body"}} =
             Message.parse("A: b\n\r\r\n\nbody")
  end

  test "normalize_line_endings turns bare LF into CRLF only" do
    assert Message.normalize_line_endings("a\nb\r\nc\r\r\n\n\r") == "a\r\nb\r\nc\r\r\n\r\n\r"
    assert Message.normalize_line_endings("") == ""
  end

  test "a message with no body" do
    assert {:ok, %{headers: [{"from", _}], body: ""}} = Message.parse("From: a@b.c")
    assert {:ok, %{headers: [], body: "body"}} = Message.parse("\r\nbody")
  end

  test "limits" do
    assert {:error, :headers_too_large} =
             Message.parse(String.duplicate("A: b\r\n", 1001) <> "\r\n")

    assert {:ok, _} = Message.parse(String.duplicate("A: b\r\n", 1000) <> "\r\n")

    assert {:error, :headers_too_large} =
             Message.parse("A: " <> String.duplicate("x", 1_048_577) <> "\r\n\r\n")

    # A bare LF counts as two bytes, as it becomes CRLF.
    assert {:ok, _} = Message.parse("A: b\r\n" <> String.duplicate(" x\r\n", 262_000) <> "\r\n")

    assert {:error, :headers_too_large} =
             Message.parse("A: b\n" <> String.duplicate(" x\n", 300_000) <> "\n")

    # A message with no empty line is all headers.
    assert {:error, :headers_too_large} = Message.parse(String.duplicate("x", 1_048_577))
    assert {:error, :headers_too_large} = Message.parse(String.duplicate("A: b\n", 300_000))
  end
end
