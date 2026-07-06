# ATT&CK Coverage Dashboard — Cloud-Trail-Detector

*Auto-generated on 2026-07-06 09:06 UTC. Run `python coverage/generate_coverage.py` to update.*

---

## Summary

| Metric | Value |
|--------|-------|
| Total rules | 6 |
| ATT&CK techniques covered | 6 |
| Tactics covered | 6 |
| Rules with test cases | 6 |
| FP tuning applied | 2 rules |

---

## Tactic Coverage

| Tactic | Rules |
|--------|-------|
| Collection | 1 |
| Credential Access | 1 |
| Defense Evasion | 1 |
| Discovery | 1 |
| Persistence | 1 |
| Privilege Escalation | 1 |

---

## Detection Rules

| Rule ID | ATT&CK ID | Technique | Tactic | Severity | Rule File | Test Coverage | Confidence |
|---------|-----------|-----------|--------|----------|-----------|---------------|------------|
| CTD-001 | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Persistence | High | `t1078_iam_key_creation.yml` | ✅ Attack + Benign | Medium |
| CTD-005 | [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Discovery | Medium | `t1087_account_discovery.yml` | ✅ Attack + Benign | Medium (requires allowlist) |
| CTD-004 | [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access | High | `t1110_brute_force.yml` | ✅ Attack + Benign | Medium |
| CTD-002 | [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage Object | Collection | Medium | `t1530_s3_enumeration.yml` | ✅ Attack + Benign | Medium |
| CTD-003 | [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Privilege Escalation | High | `t1548_role_assumption.yml` | ✅ Attack + Benign | Medium (requires allowlist) |
| CTD-006 | [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion | Critical | `t1562_disable_cloudtrail.yml` | ✅ Attack + Benign | High |

---

## False Positive Tuning Results

Measured on a mixed batch of 28 CloudTrail events (attack + benign).

| Metric | Before Tuning | After Tuning |
|--------|--------------|--------------|
| Total alerts fired | 14 | 8 |
| True positives | 8 | 8 |
| False positives | 6 | 0 |
| FP rate | 43% | 0% |
| True positives lost | — | 0 |

**FP reduction: 43% → 0% with zero detection loss.**

Suppression rules applied:
- `CTD-003`: Lambda functions assuming execution roles from internal IPs
- `CTD-005`: Compliance scanner (`compliance-scanner`) from internal network

---

## Investigation Notes

Per-technique write-ups in [`docs/investigations/`](../docs/investigations/):

- [T1078 — Valid Accounts](../docs/investigations/T1078_valid_accounts.md)
- [T1087 — Account Discovery](../docs/investigations/T1087_account_discovery.md)
- [T1110 — Brute Force](../docs/investigations/T1110_brute_force.md)
- [T1530 — Data from Cloud Storage Object](../docs/investigations/T1530_cloud_storage.md)
- [T1548 — Abuse Elevation Control Mechanism](../docs/investigations/T1548_privilege_escalation.md)
- [T1562 — Impair Defenses](../docs/investigations/T1562_impair_defenses.md)
