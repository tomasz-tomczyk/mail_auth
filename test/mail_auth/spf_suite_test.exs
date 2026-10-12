defmodule MailAuth.SPFSuiteTest do
  # The RFC 7208 test suite (openspf.org, kept by the pyspf project), run
  # against MailAuth.Resolver.Static.
  use ExUnit.Case, async: true

  alias MailAuth.Test.SPFSuite

  for {doc, doc_index} <- Enum.with_index(SPFSuite.suite()), {name, test} <- doc["tests"] do
    @doc_index doc_index
    @test test
    test "#{doc["description"]}: #{name}" do
      records = SPFSuite.records(@doc_index)

      result =
        MailAuth.SPF.check(@test["host"], @test["mailfrom"], @test["helo"],
          resolver: MailAuth.Resolver.Static,
          records: records,
          receiver: "unknown"
        )

      expected = @test["result"] |> List.wrap() |> Enum.map(&String.to_atom/1)

      assert result.result in expected,
             "expected #{inspect(expected)}, got #{inspect(result.result)} (#{inspect(result.reason)})\n" <>
               "#{@test["description"] || ""} #{@test["comment"] || ""}"

      case @test["explanation"] do
        nil ->
          :ok

        "DEFAULT" ->
          :ok

        # Compared without case: the suite writes %{ir} for IPv6 in capitals,
        # RFC 7208's own example in lowercase.
        explanation ->
          if result.result == :fail,
            do: assert(String.downcase(result.explanation) == String.downcase(explanation))
      end
    end
  end
end
