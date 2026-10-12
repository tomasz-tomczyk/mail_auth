---
description: Release a new version of mail_auth to Hex and GitHub
argument-hint: "[version, e.g. 0.2.0]"
---

Release a new version of mail_auth. The version to release: $ARGUMENTS (if empty, propose one, step 2).

Work through the steps in order. Stop and ask the user if a check fails. Every change to `main` goes through a pull request; branch protection refuses direct pushes. Run mix through mise: `mise exec -- mix ...`.

## 1. Check the starting point

- `git switch main && git pull --ff-only`, and `git status` is clean.
- The last `ci.yml` run on `main` passed: `gh run list --workflow ci.yml --branch main --limit 1`.
- `CHANGELOG.md` has entries under `## Unreleased`. If it is empty, there is nothing to release: stop and tell the user.

## 2. Pick the version

Read `## Unreleased` and the current `@version` in `mix.exs`. Follow Semantic Versioning; while on 0.x:

- a breaking change bumps the minor version (0.1.3 → 0.2.0)
- anything else bumps the patch version (0.1.3 → 0.1.4)

If the user gave a version, check it fits these rules and say so if it doesn't. If not, propose one with the reason and wait for the user to agree.

Breaking changes must come first in the section, each with what to change. Fix the order if needed.

## 3. Open the release pull request

On a branch `release/X.Y.Z`:

- `mix.exs`: set `@version "X.Y.Z"`. It is the only place the version is written.
- `README.md`: if the minor or major version changed, update the dependency line to `{:mail_auth, "~> MAJOR.MINOR"}`. `test/readme_test.exs` checks it.
- `CHANGELOG.md`: rename `## Unreleased` to `## X.Y.Z - YYYY-MM-DD` with today's date (UTC), and add a new empty `## Unreleased` above it.

Run the checks:

```sh
mise exec -- mix format --check-formatted
mise exec -- mix compile --warnings-as-errors
mise exec -- mix test --warnings-as-errors
MIX_ENV=dev mise exec -- mix docs --warnings-as-errors
MIX_ENV=dev mise exec -- mix hex.build --unpack --output /tmp/mail_auth-pkg
```

Look at the unpacked package: only `lib`, `mix.exs`, `README.md`, `LICENSE`, `CHANGELOG.md` and `hex_metadata.config`. Then delete it.

Commit as `chore: release X.Y.Z`, push, and open the pull request with `gh pr create`. Put the changelog section in the body.

## 4. Merge

Wait for every check: `gh pr checks <number> --watch`. Then show the user the changelog section and ask before merging. Merge with `gh pr merge <number> --rebase --delete-branch`.

Update local `main` and wait for the `ci.yml` run on the merged commit to pass. `release.yml` refuses a commit without a passing CI run.

## 5. Tag

```sh
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

This starts `release.yml`. It checks that the tag matches `@version`, that the changelog section is dated, and that the commit is on `main` with passing CI. Then it runs the CI jobs again on the tag.

## 6. Approve the publish

The `publish` job waits for approval of the `hex` environment. Give the user the run link (`gh run list --workflow release.yml --limit 1`). On the run page they choose "Review deployments" (a yellow box above the job graph), tick `hex`, then "Approve and deploy".

Approve from here only when the user asks you to:

```sh
env_id=$(gh api repos/tomasz-tomczyk/mail_auth/environments/hex --jq .id)
gh api -X POST repos/tomasz-tomczyk/mail_auth/actions/runs/<run-id>/pending_deployments \
  -F "environment_ids[]=$env_id" -f state=approved -f comment="Approve X.Y.Z"
```

## 7. Check the release

Watch the run to the end: `gh run watch <run-id> --exit-status`. Then check:

- hex.pm shows the version: `curl -s https://hex.pm/api/packages/mail_auth | jq .latest_version`
- HexDocs serves it: `https://mail-auth.hexdocs.pm/X.Y.Z/` has the title "MailAuth vX.Y.Z", and "view source" links point at the tag
- the GitHub release exists with the tarball and its `.sha256`: `gh release view vX.Y.Z`

If the package went up but the docs did not, run `MIX_ENV=dev mise exec -- mix hex.publish docs --yes` from a checkout of the tag; it needs the user's Hex login.

Report the links to the user.

## If something goes wrong

- A check in `release.yml` failed before publishing: fix it in a new pull request, then delete and recreate the tag (`git push origin :vX.Y.Z`, `git tag -d vX.Y.Z`) on the new commit.
- A published version has a bad bug or a security problem: release a fix, then retire the bad version with `mix hex.retire mail_auth X.Y.Z <reason> --message "Use X.Y.Z+1"`; the reason is one of `renamed`, `deprecated`, `security`, `invalid`, `other`. A security fix also gets a GitHub security advisory.
