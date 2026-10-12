"""Signs and verifies messages with dkimpy, for the interop CI job.

    python dkimpy_check.py verify MESSAGE DNS_FILE
    python dkimpy_check.py sign MESSAGE KEY DOMAIN SELECTOR [rsa|ed25519]

DNS_FILE has one record per line, `name TYPE value`, the format of
`mix mail_auth.verify --dns-file`. For Ed25519, KEY is PEM (PKCS#8) or the base64 seed.
"""

import base64
import re
import sys

import dkim


def read_dns(path):
    records = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, rtype, value = re.split(r"\s+", line, maxsplit=2)
            if rtype.upper() != "TXT":
                continue
            if value.startswith('"'):
                value = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', value))
            records.setdefault(name.lower().rstrip("."), []).append(value)
    return records


def verify(message_path, dns_path):
    records = read_dns(dns_path)

    def dnsfunc(name, timeout=5):
        name = name.decode() if isinstance(name, bytes) else name
        values = records.get(name.lower().rstrip("."), [])
        return values[0].encode() if values else b""

    with open(message_path, "rb") as f:
        message = f.read()

    d = dkim.DKIM(message)
    count = len([h for h in d.headers if h[0].lower() == b"dkim-signature"])
    if count == 0:
        print("no signature")
        return 1
    for i in range(count):
        if not d.verify(idx=i, dnsfunc=dnsfunc):
            print(f"signature {i} failed")
            return 1
    print(f"{count} signature(s) passed")
    return 0


def sign(message_path, key_path, domain, selector, kind="rsa"):
    with open(message_path, "rb") as f:
        message = f.read()
    with open(key_path, "rb") as f:
        key = f.read().strip()
    if kind == "ed25519" and key.startswith(b"-----BEGIN"):
        # dkimpy wants the base64 seed; a PKCS#8 Ed25519 key ends with it.
        der = base64.b64decode(b"".join(key.splitlines()[1:-1]))
        key = base64.b64encode(der[-32:])

    signature = dkim.sign(
        message,
        selector.encode(),
        domain.encode(),
        key,
        canonicalize=(b"relaxed", b"relaxed"),
        include_headers=[b"from", b"to", b"subject", b"date", b"message-id"],
        signature_algorithm=b"ed25519-sha256" if kind == "ed25519" else b"rsa-sha256",
    )
    sys.stdout.buffer.write(signature + message)
    return 0


if __name__ == "__main__":
    command, *args = sys.argv[1:]
    sys.exit(verify(*args) if command == "verify" else sign(*args))
