defmodule MailAuth.MessageTest do
  use ExUnit.Case, async: true

  alias MailAuth.Message

  test "splits headers and body, keeping folding" do
    raw = "From: a@b.c\r\nSubject: one\r\n two\r\n\r\nbody\r\n\r\n"
    assert {:ok, msg} = Message.parse(raw)
    assert msg.headers == [{"from", "From: a@b.c\r\n"}, {"subject", "Subject: one\r\n two\r\n"}]
    assert msg.body == "body\r\n\r\n"
  end

  test "reads bare LF as CRLF and changes nothing else" do
    assert {:ok, %{headers: [{"from", "From: a@b.c\r\n"}], body: "x\r\ny\r\nz\r"}} =
             Message.parse("From: a@b.c\n\nx\ny\r\nz\r")
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
  end
end
