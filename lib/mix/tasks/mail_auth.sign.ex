defmodule Mix.Tasks.MailAuth.Sign do
  @shortdoc "Signs a message with DKIM"

  @moduledoc """
  Signs a message with DKIM and prints the signed message.

      mix mail_auth.sign message.eml --domain example.com --selector s1 --key key.pem

  Options:

    * `--domain`, `--selector`, `--key` (required): the signing domain, the
      selector, and a file with the private key in PEM
    * `--canonicalization`: `relaxed/relaxed` (the default), `simple/simple`,
      `relaxed/simple` or `simple/relaxed`
    * `--identity`: the `i=` tag
    * `--expires-in`: seconds until the signature expires
    * `--now`: the signing time, in Unix seconds
  """

  use Mix.Task

  alias MailAuth.CLI

  @switches [
    domain: :string,
    selector: :string,
    key: :string,
    canonicalization: :string,
    identity: :string,
    expires_in: :integer,
    now: :integer
  ]

  @impl Mix.Task
  def run(args) do
    {parsed, rest} = OptionParser.parse!(args, strict: @switches)

    path =
      List.first(rest) ||
        Mix.raise("Usage: mix mail_auth.sign message.eml --domain d --selector s --key key.pem")

    CLI.start()

    for key <- [:domain, :selector, :key], is_nil(parsed[key]) do
      Mix.raise("--#{key} is required")
    end

    opts =
      [
        domain: parsed[:domain],
        selector: parsed[:selector],
        private_key: CLI.read!(parsed[:key]),
        canonicalization: canonicalization(parsed[:canonicalization] || "relaxed/relaxed")
      ] ++ Keyword.take(parsed, [:identity, :expires_in, :now])

    case MailAuth.DKIM.sign(CLI.read!(path), opts) do
      {:ok, signed} ->
        # Raw bytes: a unicode stdout would re-encode 8-bit text and break
        # the signature.
        :ok = :io.setopts(:standard_io, encoding: :latin1)
        IO.binwrite(signed)

      {:error, reason} ->
        Mix.raise("Could not sign: #{reason}")
    end
  end

  defp canonicalization(text) do
    case String.split(text, "/") do
      [h, b] when h in ["simple", "relaxed"] and b in ["simple", "relaxed"] ->
        {canon(h), canon(b)}

      _ ->
        Mix.raise("--canonicalization must be header/body, each simple or relaxed")
    end
  end

  defp canon("simple"), do: :simple
  defp canon("relaxed"), do: :relaxed
end
