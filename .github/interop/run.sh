#!/usr/bin/env bash
# Signs the messages in messages/ with this library and verifies them with
# dkimpy, then the other way round. A bug shared by our signer and our
# verifier can't hide from this.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
python="${PYTHON:-python3}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mix mail_auth.gen_key --domain example.com --selector rsa --out "$work/rsa.pem" > "$work/rsa.txt"
mix mail_auth.gen_key --domain example.com --selector ed --ed25519 --out "$work/ed.pem" > "$work/ed.txt"

{
  echo "rsa._domainkey.example.com TXT \"$(tail -1 "$work/rsa.txt")\""
  echo "ed._domainkey.example.com TXT \"$(tail -1 "$work/ed.txt")\""
  echo '_dmarc.example.com TXT "v=DMARC1; p=reject"'
} > "$work/dns.txt"

for message in "$here"/messages/*.eml; do
  name="$(basename "$message")"

  for canonicalization in relaxed/relaxed simple/simple relaxed/simple simple/relaxed; do
    for key in rsa ed; do
      mix mail_auth.sign "$message" --domain example.com --selector "$key" --key "$work/$key.pem" \
        --canonicalization "$canonicalization" > "$work/ours.eml"
      echo -n "ours -> dkimpy  $name $key $canonicalization: "
      "$python" "$here/dkimpy_check.py" verify "$work/ours.eml" "$work/dns.txt"
    done
  done

  "$python" "$here/dkimpy_check.py" sign "$message" "$work/rsa.pem" example.com rsa rsa > "$work/theirs.eml"
  echo "dkimpy -> ours  $name rsa:"
  mix mail_auth.verify "$work/theirs.eml" --dns-file "$work/dns.txt"

  "$python" "$here/dkimpy_check.py" sign "$message" "$work/ed.pem" example.com ed ed25519 > "$work/theirs.eml"
  echo "dkimpy -> ours  $name ed25519:"
  mix mail_auth.verify "$work/theirs.eml" --dns-file "$work/dns.txt"
done

echo "All interop checks passed."
