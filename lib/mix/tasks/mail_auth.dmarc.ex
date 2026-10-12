defmodule Mix.Tasks.MailAuth.Dmarc do
  @shortdoc "Looks up a domain's DMARC record"

  @moduledoc """
  Looks up the DMARC record that applies to a domain, where it was found,
  and the organizational domain.

      mix mail_auth.dmarc example.com

  Options: `--json`, and `--dns-file` as for `mix mail_auth.verify`.
  """

  use Mix.Task

  alias MailAuth.CLI

  @impl Mix.Task
  def run(args) do
    {parsed, rest} = OptionParser.parse!(args, strict: [json: :boolean, dns_file: :string])
    domain = List.first(rest) || Mix.raise("Usage: mix mail_auth.dmarc example.com")
    CLI.start()

    case MailAuth.DMARC.lookup(domain, CLI.resolver_opts(parsed)) do
      {:ok, record, org} ->
        if parsed[:json] do
          IO.puts(CLI.json(%{record: record, organizational_domain: org}))
        else
          IO.puts("""
          Record at:             _dmarc.#{record.domain}
          Organizational domain: #{org}
          Policy:                p=#{record.p || "-"} sp=#{record.sp || "-"} np=#{record.np || "-"}#{if record.testing?, do: " (testing)", else: ""}
          Alignment:             adkim=#{record.adkim} aspf=#{record.aspf}
          Public suffix:         psd=#{record.psd}
          Reports:               rua=#{CLI.list(record.rua)} ruf=#{CLI.list(record.ruf)}
          Warnings:              #{CLI.list(record.warnings)}\
          """)
        end

      {:error, reason} ->
        IO.puts("No DMARC record for #{domain}: #{reason}")
        exit({:shutdown, 1})
    end
  end
end
