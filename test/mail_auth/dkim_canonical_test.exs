defmodule MailAuth.DKIM.CanonicalTest do
  # Canonicalization tables (RFC 6376 section 3.4).
  use ExUnit.Case, async: true

  alias MailAuth.DKIM.Canonical

  defp body(raw, algorithm),
    do: raw |> MailAuth.Message.normalize_line_endings() |> Canonical.body(algorithm)

  for {input, expected} <- [
        {"", "\r\n"},
        {"\r\n", "\r\n"},
        {"\r\n\r\n\r\n", "\r\n"},
        {"Hey\r\n\r\n", "Hey\r\n"},
        {"Hey\r\nHow r u?\r\n\r\n\r\n", "Hey\r\nHow r u?\r\n"},
        {"Hey\r\n\r\nHow r u?", "Hey\r\n\r\nHow r u?\r\n"},
        {"What about\nLF endings?\n\n", "What about\r\nLF endings?\r\n"},
        {"\r\n\r\n", "\r\n"},
        {"\r\n\r", "\r\n\r\r\n"},
        {"\r\n\r\nhey\n\n", "\r\n\r\nhey\r\n"}
      ] do
    test "simple body #{inspect(input)}" do
      assert body(unquote(input), :simple) == unquote(expected)
    end
  end

  for {input, expected} <- [
        {"", ""},
        {"\r\n", ""},
        {"\r\n\r\n\r\n", ""},
        {"Hey\r\n\r\n", "Hey\r\n"},
        {"Hey\r\nHow r u?\r\n\r\n\r\n", "Hey\r\nHow r u?\r\n"},
        {"Hey\r\n\r\nHow r u?", "Hey\r\n\r\nHow r u?\r\n"},
        {"Hey \t you!", "Hey you!\r\n"},
        {"Hey \t \r\nyou!", "Hey\r\nyou!\r\n"},
        {"Hey\r\n \t you!\r\n", "Hey\r\n you!\r\n"},
        {"Hey\r\n \t \r\n \r\n", "Hey\r\n"}
      ] do
    test "relaxed body #{inspect(input)}" do
      assert body(unquote(input), :relaxed) == unquote(expected)
    end
  end

  for {input, expected} <- [
        {"SubjeCT: Your Name\r\n", "subject:Your Name\r\n"},
        {"Subject \t:\t Your Name\t \r\n", "subject:Your Name\r\n"},
        {"Subject \t:\t Kimi \t \r\n No \t\r\n Na Wa\r\n", "subject:Kimi No Na Wa\r\n"},
        {"Subject \t:\t Ki \tmi \t \r\n No \t\r\n Na Wa\r\n", "subject:Ki mi No Na Wa\r\n"}
      ] do
    test "relaxed header #{inspect(input)}" do
      assert Canonical.header(unquote(input), :relaxed) == unquote(expected)
    end
  end

  test "simple headers are unchanged" do
    assert Canonical.header("SubjeCT : Your  Name\r\n", :simple) == "SubjeCT : Your  Name\r\n"
  end
end
