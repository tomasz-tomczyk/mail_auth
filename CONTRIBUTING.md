# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Setup

The versions of Elixir and Erlang are in `.tool-versions`, which mise and asdf read.

```sh
mix deps.get
mix test
```

No test reaches the network. Tests use `MailAuth.Resolver.Static`. The tests that check `MailAuth.Resolver.Inet` against real DNS are tagged and skipped by default:

```sh
mix test --only network
```

Property tests run 100 times each by default. To run them longer:

```sh
STREAM_DATA_MAX_RUNS=20000 mix test test/mail_auth/property_test.exs
```

## Before you open a pull request

```sh
mix format --check-formatted
mix compile --warnings-as-errors
mix test --warnings-as-errors
mix docs --warnings-as-errors
```

- Add a test for every change in behaviour. A new reason or warning goes in the README's table and needs a test; `test/readme_test.exs` checks this.
- Add a line to the "Unreleased" section of `CHANGELOG.md`.
- Write commit messages as [Conventional Commits](https://www.conventionalcommits.org/): `feat: ...`, `fix: ...`, `docs: ...`, `test: ...`, `chore: ...`, `ci: ...`, `refactor: ...`. A breaking change gets `!` (`feat!: ...`) and a `BREAKING CHANGE:` footer.

## Interop with dkimpy

The `interop` CI job signs with this library and verifies with dkimpy, and the other way round. To run it locally:

```sh
python -m venv .venv && .venv/bin/pip install -r .github/interop/requirements.txt
PYTHON=.venv/bin/python .github/interop/run.sh
```

## Security

Report security problems privately, as `SECURITY.md` says, not in a public issue.
