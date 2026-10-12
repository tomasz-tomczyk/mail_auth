defmodule Mix.Tasks.MailAuth.Verify do
  @shortdoc "Checks DKIM, SPF and DMARC of a message"

  @moduledoc """
  Checks DKIM, SPF and DMARC of a message and prints every result.

      mix mail_auth.verify message.eml
      mix mail_auth.verify message.eml --ip 192.0.2.1 --mail-from a@example.com --helo mx.example.com

  Options:

    * `--ip`, `--mail-from`, `--helo`: the SMTP session, to run SPF
    * `--json`: print the results as JSON
    * `--dns-file`: answer DNS from a file instead of the network, one record
      per line (`name TYPE value`, see `MailAuth.Resolver.Static.parse_file/1`)
    * `--now`: the time to check signatures against, in Unix seconds

  Exits with status 1 when DMARC did not pass.
  """

  use Mix.Task

  alias MailAuth.CLI

  @switches [
    ip: :string,
    mail_from: :string,
    helo: :string,
    json: :boolean,
    dns_file: :string,
    now: :integer
  ]

  @impl Mix.Task
  def run(args) do
    {parsed, rest} = OptionParser.parse!(args, strict: @switches)
    path = List.first(rest) || Mix.raise("Usage: mix mail_auth.verify message.eml [options]")
    CLI.start()

    opts =
      CLI.resolver_opts(parsed) ++
        Keyword.take(parsed, [:ip, :mail_from, :helo, :now])

    result = path |> CLI.read!() |> MailAuth.authenticate(opts)

    if parsed[:json], do: IO.puts(CLI.json(result)), else: print(result)

    unless MailAuth.Result.dmarc_pass?(result), do: exit({:shutdown, 1})
  end

  defp print(result) do
    IO.puts("From domain: #{result.from_domain || "-"}\n")
    IO.puts("DKIM")

    if result.dkim == [], do: IO.puts("  none  (no signature)")

    for d <- result.dkim do
      IO.puts("  #{label(d.result, d.reason)}  d=#{d.domain} s=#{d.selector} a=#{d.algorithm}")

      IO.puts(
        "        key: #{d.key_bits || "-"} bits#{if d.testing?, do: " (testing)", else: ""}, " <>
          "signed headers: #{Enum.join(d.signed_headers, ":")}"
      )

      if d.warnings != [], do: IO.puts("        warnings: #{CLI.list(d.warnings)}")
    end

    s = result.spf
    IO.puts("\nSPF")

    IO.puts(
      "  #{label(s.result, s.reason)}  #{if s.domain, do: "domain=#{s.domain} ", else: ""}#{if s.mechanism, do: "mechanism=#{s.mechanism}", else: ""}"
    )

    if s.explanation, do: IO.puts("        explanation: #{s.explanation}")

    if m = result.dmarc do
      IO.puts("\nDMARC")
      IO.puts("  #{label(m.result, m.reason)}  aligned by: #{CLI.list(m.aligned_by)}")

      IO.puts(
        "        policy: #{m.policy || "-"}, disposition: #{m.disposition}, " <>
          "record at: #{m.record_domain || "-"}, organizational domain: #{m.organizational_domain || "-"}"
      )

      if m.warnings != [], do: IO.puts("        warnings: #{CLI.list(m.warnings)}")
    end
  end

  defp label(result, nil), do: String.pad_trailing(to_string(result), 9)
  defp label(result, reason), do: "#{String.pad_trailing(to_string(result), 9)} (#{reason})"
end
