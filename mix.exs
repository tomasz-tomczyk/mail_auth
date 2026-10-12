defmodule MailAuth.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/tomasz-tomczyk/mail_auth"

  def project do
    [
      app: :mail_auth,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      name: "MailAuth",
      source_url: @source_url
    ]
  end

  def application do
    [extra_applications: [:crypto, :public_key, :xmerl]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:idna, "~> 7.1"},
      {:telemetry, "~> 1.4"},
      {:stream_data, "~> 1.4", only: [:dev, :test]},
      {:ex_doc, "~> 0.40", only: :dev, runtime: false}
    ]
  end

  defp description do
    "Verifies DKIM, SPF and DMARC, signs mail with DKIM, and reads and writes Authentication-Results headers."
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md",
        "RFC 6376 (DKIM)" => "https://www.rfc-editor.org/rfc/rfc6376",
        "RFC 7208 (SPF)" => "https://www.rfc-editor.org/rfc/rfc7208",
        "RFC 9989 (DMARC)" => "https://www.rfc-editor.org/rfc/rfc9989",
        "RFC 8601 (Authentication-Results)" => "https://www.rfc-editor.org/rfc/rfc8601"
      },
      files: ~w(lib mix.exs README.md LICENSE CHANGELOG.md)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      extras: [
        "README.md",
        "CHANGELOG.md",
        "guides/dkim.md",
        "guides/dmarc.md",
        "guides/spf.md",
        "guides/authentication-results.md",
        "guides/dns.md"
      ],
      groups_for_extras: [Guides: ~r{guides/}],
      groups_for_modules: [
        DKIM: [MailAuth.DKIM, MailAuth.DKIM.Result],
        DMARC: [
          MailAuth.DMARC,
          MailAuth.DMARC.Result,
          MailAuth.DMARC.Record,
          MailAuth.DMARC.Report
        ],
        SPF: [MailAuth.SPF, MailAuth.SPF.Result],
        Headers: [MailAuth.AuthenticationResults, MailAuth.AuthenticationResults.Method],
        DNS: [
          MailAuth.Resolver,
          MailAuth.Resolver.Inet,
          MailAuth.Resolver.Static,
          MailAuth.Resolver.Cached
        ]
      ]
    ]
  end
end
