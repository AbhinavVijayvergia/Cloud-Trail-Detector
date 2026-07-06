# T1078 — Valid Accounts (IAM Access Key Creation)

## What the attack does
The attacker already has access to an IAM user — either through phishing, credential stuffing, or a leaked key. They create a **new access key** for that user. This gives them a second, independent way back into the account even if the original credentials are rotated. It's a persistence technique — the attacker is setting up a backdoor.

## Why it matters
Access keys are long-lived credentials (no expiry by default). A malicious key can sit quietly for months. AWS accounts average ~3 months between compromise and detection — keys are a major reason why.

## What the detection catches
- Any `CreateAccessKey` API call via IAM
- Fires regardless of who makes the call — useful for catching both external attackers and insider threats

## What it might miss
- Legitimate key rotation by CI/CD pipelines or administrators — these will fire the rule too (false positives in real environments)
- Attacker using an existing compromised key without creating a new one — no new key = no alert
- Keys created via AWS Console vs CLI both appear as `CreateAccessKey` in CloudTrail, so no differentiation there

## Detection confidence
Medium — high signal event, but common legitimate use means FP tuning is needed in production.