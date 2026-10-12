defmodule Mix.Tasks.MailAuth.GenKey do
  @shortdoc "Generates a DKIM key and its DNS record"

  @moduledoc """
  Generates a DKIM key and prints the TXT record to publish.

      mix mail_auth.gen_key --domain example.com --selector s1
      mix mail_auth.gen_key --domain example.com --selector s1 --ed25519 --out s1.pem

  Options:

    * `--domain`, `--selector`: where the record goes
    * `--ed25519`: an Ed25519 key instead of RSA
    * `--bits`: the RSA key size. Default 2048
    * `--out`: write the private key to this file instead of printing it
  """

  use Mix.Task

  alias MailAuth.CLI

  @impl Mix.Task
  def run(args) do
    {parsed, _} =
      OptionParser.parse!(args,
        strict: [
          domain: :string,
          selector: :string,
          ed25519: :boolean,
          bits: :integer,
          out: :string
        ]
      )

    CLI.start()
    type = if parsed[:ed25519], do: :ed25519, else: :rsa
    key = MailAuth.DKIM.generate_key(type, Keyword.take(parsed, [:domain, :selector, :bits]))

    case parsed[:out] do
      nil ->
        IO.write(key.private_key)

      path ->
        File.write!(path, key.private_key)
        File.chmod!(path, 0o600)
        IO.puts("Private key written to #{path}")
    end

    IO.puts(
      "\nPublish this TXT record#{if key[:dns_name], do: " at #{key.dns_name}", else: ""}:\n"
    )

    IO.puts(key.dns_record)
  end
end
