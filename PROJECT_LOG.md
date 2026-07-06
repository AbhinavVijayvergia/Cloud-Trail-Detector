# Project Log — Cloud-Trail-Detector

Dated record of build progress.

---

**[2026-07-04]** Phase 0 complete — repo created, folder structure scaffolded, README skeleton with architecture/tools/structure sections, .gitignore, requirements.txt.

**[2026-07-05]** Phase 1 complete — detection rule schema defined, 3 YAML rules written (T1078, T1530, T1548), simulated CloudTrail log generator built, detection engine built and validated (5 alerts, 0 false positives).

**[2026-07-06]** Phase 2 complete — 3 new rules added (T1110, T1087, T1562), test harness built (6/6 pass), GitHub Actions CI pipeline live and green (14 alerts, 0 FP across all benign logs).