# mail_auth

An Elixir library that checks DKIM, SPF and DMARC, signs mail with DKIM, and reads and writes `Authentication-Results:` headers. Module `MailAuth`, package `mail_auth` on Hex.

## Rules

- **Conventional Commits** for every commit: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `perf:`, `chore:`, `ci:`, `build:`. Add a scope when it helps (`feat(dkim): ...`). A breaking change gets `!` and a `BREAKING CHANGE:` footer. One logical change per commit.
- **Never commit `SPEC.md`.** It is the design spec, kept out of the repository by `.gitignore`.
- **Plain language** in docs, comments and commit messages. Short sentences, no filler.
- **Don't name other projects** in code or docs, unless a license needs it. The go-msgauth notice in `LICENSE` and the one credit line in the README are required by its MIT license.
- **Follow the Elixir library guidelines** (https://hexdocs.pm/elixir/library-guidelines.html): no application environment config, no `Application` module, `~>` version requirements, dev and test deps marked `only:`.
- **No credo, dialyxir or mix_audit.** Formatting, `--warnings-as-errors` and `mix hex.audit` are the checks.
- **No NIFs.** Only `:crypto`, `:public_key`, `:inet_res`, `:xmerl`, `:zlib` and `:zip` from OTP, plus `idna` and `telemetry`.

## Security rules

Input comes from strangers: messages, DNS answers, reports.

- Never turn a header, DNS string or XML name into an atom. Map known values to atoms with explicit clauses.
- Bound everything: `:deadline`, `:timeout`, SPF's lookup limits, 4 KB TXT records, 4096-bit RSA keys, 1000 headers and 1 MB of headers, 50 MB reports.
- A DNS failure is `:temperror`, never `:fail`.
- Never log or put message content or keys in telemetry.
- Public parsers must not raise on any input. The property tests check this.

## Layout

- `lib/mail_auth.ex`: `authenticate/2`
- `lib/mail_auth/dkim.ex`, `dkim/`: verify, sign, keys, canonicalization
- `lib/mail_auth/dmarc.ex`, `dmarc/`: tree walk, alignment, policy, records, reports
- `lib/mail_auth/spf.ex`, `spf/`: check_host, record and macro parsers
- `lib/mail_auth/authentication_results.ex`: format and parse
- `lib/mail_auth/resolver*.ex`, `lib/mail_auth/dns.ex`: resolvers; every query goes through `MailAuth.DNS.lookup/3`, which applies the deadline and emits telemetry
- `lib/mail_auth/message.ex`, `tags.ex`, `domain.ex`, `address.ex`: internal parsers (`@moduledoc false`)
- `lib/mix/tasks/`: the `mix mail_auth.*` tools
- `test/fixtures/spf/`: the RFC 7208 test suite (YAML as published, JSON as read by the tests)
- `.github/interop/`: the dkimpy interop check

## Commands

Versions are pinned in `.tool-versions`; run commands through mise (`mise exec -- mix ...`).

```sh
mix test                                  # no network
mix test --only network                   # Inet resolver against real DNS
STREAM_DATA_MAX_RUNS=20000 mix test test/mail_auth/property_test.exs
mix format --check-formatted
mix compile --warnings-as-errors && mix test --warnings-as-errors
mix docs --warnings-as-errors
.github/interop/run.sh                    # needs dkimpy: pip install -r .github/interop/requirements.txt
```

## Tests

- No test reaches the network except those tagged `:network`. Use `MailAuth.Resolver.Static`.
- Every reason and warning in the README's tables needs a test. `test/readme_test.exs` fails otherwise.
- A new parser gets a property test in `test/mail_auth/property_test.exs`.

## Releases

`@version` in `mix.exs` is the only place the version is written. The README's dependency line (`~> MAJOR.MINOR`) is checked by a test. A release needs a `## X.Y.Z - YYYY-MM-DD` section in `CHANGELOG.md`; `release.yml` checks it.
