# Security

## Reporting a problem

Please report security problems privately, with GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Don't open a public issue.

A fix is released for the newest minor version, with a GitHub security advisory and an entry in the Erlang Ecosystem Foundation's advisory database.

## What counts

MailAuth reads input from strangers: messages, DNS answers and reports. These are security problems:

- a forged message that gets a DKIM or DMARC pass
- input that makes a call raise, use much memory, or run past its `:deadline`
- input that creates atoms
- message content or keys in logs or telemetry

## What MailAuth does not do

- It does not check DNSSEC. Someone who can change DNS answers on the way can fake a pass.
- A pass proves which domain sent a message, not which person, and not that it was meant for you. See "What a pass means" in the README.
