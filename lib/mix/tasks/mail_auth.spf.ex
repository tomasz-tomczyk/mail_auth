defmodule Mix.Tasks.MailAuth.Spf do
  @shortdoc "Checks SPF for a domain and an IP"

  @moduledoc """
  Checks whether an IP may send mail for a domain, and shows each record
  evaluated on the way through `include` and `redirect`.

      mix mail_auth.spf example.com 192.0.2.1

  Options:

    * `--mail-from`: the full `MAIL FROM` address. Default `postmaster@<domain>`
    * `--helo`: the HELO name
    * `--json`, `--dns-file`: as for `mix mail_auth.verify`
  """

  use Mix.Task

  alias MailAuth.CLI

  @impl Mix.Task
  def run(args) do
    {parsed, rest} =
      OptionParser.parse!(args,
        strict: [json: :boolean, dns_file: :string, mail_from: :string, helo: :string]
      )

    [domain, ip] =
      case rest do
        [domain, ip] -> [domain, ip]
        _ -> Mix.raise("Usage: mix mail_auth.spf example.com 192.0.2.1")
      end

    CLI.start()
    mail_from = parsed[:mail_from] || "postmaster@" <> domain
    result = MailAuth.SPF.check(ip, mail_from, parsed[:helo], CLI.resolver_opts(parsed))

    if parsed[:json] do
      IO.puts(CLI.json(result))
    else
      for {{name, record}, depth} <- Enum.with_index(result.trace) do
        IO.puts(String.duplicate("  ", min(depth, 1)) <> "#{name}: #{record}")
      end

      IO.puts("""

      Result:      #{result.result}#{if result.reason, do: " (#{result.reason})", else: ""}
      Mechanism:   #{result.mechanism || "-"}
      Explanation: #{result.explanation || "-"}
      Warnings:    #{CLI.list(result.warnings)}\
      """)
    end
  end
end
