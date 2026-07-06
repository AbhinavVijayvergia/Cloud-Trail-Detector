# T1530 — Data from Cloud Storage Object (S3 Enumeration)

## What the attack does
After gaining initial access, the attacker maps out S3 buckets looking for valuable data — database dumps, config files, API secrets, customer PII. The sequence is: `ListBuckets` (what buckets exist?) → `GetBucketAcl` (who can access them?) → `ListObjects` (what files are inside?). This is reconnaissance targeting data at rest.

## Why it matters
S3 misconfigurations are one of the most common causes of cloud data breaches. Attackers specifically target buckets named things like `backup`, `db-dump`, `config`, `prod-data`. A few API calls can reveal an entire company's sensitive data layout.

## What the detection catches
- The enumeration sequence: ListBuckets, GetBucketAcl, ListObjects
- Any one of these events from an unexpected user triggers an alert
- Multi-event pattern in the simulated log shows the realistic attack chain

## What it might miss
- `GetObject` on a specific known file — this is normal app behavior and intentionally excluded
- Attacker who already knows the bucket name and goes straight to `GetObject` — skips enumeration entirely, evades this rule
- Slow enumeration spread across hours — harder to correlate without time-windowed rules (not implemented here)

## Detection confidence
Medium — enumeration is suspicious but legitimate tools (AWS CLI, backup scripts) do the same things.