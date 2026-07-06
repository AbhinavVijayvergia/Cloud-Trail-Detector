# Cloud-Trail-Detector

> CI/CD-tested detection-as-code pipeline for AWS CloudTrail with MITRE ATT&CK-mapped rules and automated validation.

[![CI — Detection Rules](https://github.com/AbhinavVijayvergia/Cloud-Trail-Detector/actions/workflows/ci.yml/badge.svg)](https://github.com/AbhinavVijayvergia/Cloud-Trail-Detector/actions)

---

## What This Is

A detection engineering pipeline that:
- Ingests **AWS CloudTrail** JSON logs (simulated, realistic events)
- Evaluates **YAML-defined detection rules**, each mapped to a **MITRE ATT&CK** technique
- **Auto-validates** every rule against simulated attack scenarios via **GitHub Actions CI**
- Measures and reduces **false positives** with a tuning layer
- Generates an **ATT&CK coverage dashboard** showing detection coverage and confidence

Built entirely on AWS Free Tier. No paid infrastructure.

---

## Architecture

<!-- Phase 4: Replace with Mermaid diagram -->

*Architecture diagram will be added in Phase 4.*

---

## Tools & Versions

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.10+ | Detection engine, log generator, tests |
| PyYAML | latest | Parse YAML detection rules |
| GitHub Actions | N/A | CI/CD pipeline for rule validation |
| AWS CloudTrail | N/A | Log format (simulated, not live) |
| MITRE ATT&CK | v15 | Technique mapping framework |

---

## Repo Structure

    Cloud-Trail-Detector/
    ├── detection_engine/    # Core engine — loads rules, evaluates logs
    ├── rules/               # YAML detection rules (1 per ATT&CK technique)
    ├── log_generator/       # Generates simulated CloudTrail JSON logs
    ├── tests/test_logs/     # CI test cases — attack + benign logs per rule
    ├── tuning/              # False-positive allowlists and suppression config
    ├── coverage/            # Auto-generated ATT&CK coverage dashboard
    ├── screenshots/         # Evidence screenshots for README
    ├── docs/investigations/ # Per-technique investigation write-ups
    └── .github/workflows/   # GitHub Actions CI pipeline

---

## Detection Rules

| # | ATT&CK ID | Technique | Rule File | Severity |
|---|-----------|-----------|-----------|----------|
| 1 | T1078 | Valid Accounts | `t1078_iam_key_creation.yml` | High |
| 2 | T1530 | Data from Cloud Storage Object | `t1530_s3_enumeration.yml` | Medium |
| 3 | T1548 | Abuse Elevation Control Mechanism | `t1548_role_assumption.yml` | High |
| 4 | T1110 | Brute Force | `t1110_brute_force.yml` | High |
| 5 | T1087 | Account Discovery | `t1087_account_discovery.yml` | Medium |
| 6 | T1562 | Impair Defenses | `t1562_disable_cloudtrail.yml` | Critical |

---

## Results

## Results

- **6 ATT&CK techniques** covered across 4 tactics (Persistence, Collection, Privilege Escalation, Credential Access, Discovery, Defense Evasion)
- **14 alerts** generated across 6 simulated attack scenarios
- **0 false positives** across all benign test logs
- **CI pipeline**: all 6 rules pass automated validation on every push

See [`coverage/COVERAGE.md`](coverage/COVERAGE.md) for the full ATT&CK coverage matrix (Phase 3).

---

## How to Run

**Requirements**: Python 3.10+, PyYAML

```bash
# Install dependencies
pip install -r requirements.txt

# Generate simulated attack logs
python -m log_generator.generate

# Run detection engine against all test logs
python -m detection_engine.engine

---

## Coverage Dashboard

See [COVERAGE.md](coverage/COVERAGE.md) for the full ATT&CK technique coverage matrix.

---

## Project Log

See [PROJECT_LOG.md](PROJECT_LOG.md) for dated build progress.

---

## Author

**Abhinav Vijayvergia**
- GitHub: [@AbhinavVijayvergia](https://github.com/AbhinavVijayvergia)