# T1110 — Brute Force (Console Login Failures)

## What the attack does
The attacker repeatedly attempts to log into the AWS Management Console with different passwords. Each failed attempt generates a `ConsoleLogin` event with `errorMessage: "Failed authentication"`. Tools like Hydra or custom scripts can attempt hundreds of logins per minute.

## Why it matters
AWS root accounts and IAM users without MFA are vulnerable to brute force. A successful brute force on an admin account = immediate full account access. AWS doesn't lock accounts after N failures by default — it relies on detection to catch this.

## What the detection catches
- Failed `ConsoleLogin` events from `signin.amazonaws.com`
- Successful logins have no `errorMessage` — the rule specifically matches on failure
- The simulated log shows 5 failures in 40 seconds — a realistic brute force pattern

## What it might miss
- Slow brute force (1 attempt per hour) — looks like a normal user forgetting their password
- Distributed brute force from multiple IPs — each IP only fails once, no single IP looks suspicious
- Credential stuffing (using a list of known leaked passwords) — succeeds faster, may only fail a few times before finding a valid combo

## Detection confidence
High for high-volume attacks. Low for slow or distributed attacks — time-windowed correlation needed for full coverage.