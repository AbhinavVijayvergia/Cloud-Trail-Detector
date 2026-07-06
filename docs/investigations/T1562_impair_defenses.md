# T1562 — Impair Defenses (CloudTrail Logging Disabled)

## What the attack does
The attacker calls `StopLogging` or `DeleteTrail` on CloudTrail to turn off the audit log. Everything they do after this point is invisible — no CloudTrail events, no evidence for incident response. It's the cloud equivalent of smashing a security camera before committing a crime.

## Why it matters
This is the most dangerous technique in this rule set. Once logging is disabled, detection is blind. Attackers who are sophisticated enough to think about covering their tracks are likely planning a serious follow-on attack (data exfiltration, ransomware, backdoor installation). Detecting and responding to this within minutes is critical.

## What the detection catches
- `StopLogging` — pauses CloudTrail without deleting the trail configuration
- `DeleteTrail` — permanently removes the trail
- Both are caught by the rule regardless of who calls them

## What it might miss
- Attacker who modifies CloudTrail to exclude specific event types instead of stopping it entirely — a subtler evasion that doesn't trigger StopLogging
- CloudTrail data events (S3 object-level logging) can be disabled separately — not caught here
- Multi-region trail vs single-region: stopping a regional trail while a multi-region trail still runs may look like a false stop

## Detection confidence
High — there are very few legitimate reasons to stop CloudTrail logging. This rule has the lowest FP rate of all 6.