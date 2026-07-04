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

| # | ATT&CK ID | Technique | Rule File | Status |
|---|-----------|-----------|-----------|--------|
| — | — | — | — | Coming Phase 1 |

---

## Results

*Results will be populated as phases are completed.*

---

## How to Run

*Instructions will be added after Phase 1.*

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