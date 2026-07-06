# T1087 — Account Discovery (IAM User Enumeration)

## What the attack does
After gaining initial access, the attacker runs IAM enumeration to understand the account structure: `ListUsers` (all accounts), `ListGroups` (permission groups), `ListPolicies` (what permissions exist), `GetAccountAuthorizationDetails` (full picture in one call). This reconnaissance informs the next attack step — the attacker knows who has admin access and what roles to target.

## Why it matters
Without knowing the account structure, an attacker is blind. Enumeration turns partial access into a roadmap. In a well-structured AWS account, the IAM layout reveals high-value targets (service accounts, admin roles, cross-account trust relationships).

## What the detection catches
- Broad IAM listing operations from unexpected users
- The sequence of ListUsers → ListGroups → ListPolicies in quick succession is a strong attack signal

## What it might miss
- Legitimate audit tools (AWS Config, Security Hub, compliance scanners) do the same enumeration on a schedule
- After tuning: suppressed `compliance-scanner` from internal network IP
- `GetAccountAuthorizationDetails` is the most powerful single call (returns everything at once) — if an attacker uses only this, the rule still catches it

## Detection confidence
Medium — high FP rate without tuning due to legitimate audit activity. After tuning, confidence improves significantly.