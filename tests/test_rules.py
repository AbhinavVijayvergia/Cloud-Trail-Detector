"""
CI Test Harness — Cloud-Trail-Detector
Runs each detection rule against its attack log (should fire)
and benign log (should NOT fire). Exits with code 1 if any test fails.
"""

import os
import sys

# Add project root to path so we can import the engine
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detection_engine.engine import run_detection

# Project paths
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
RULES_DIR = os.path.join(PROJECT_ROOT, "rules")
TEST_LOGS_DIR = os.path.join(PROJECT_ROOT, "tests", "test_logs")


# Test cases: each entry defines one rule's expected behavior
# "attack_log" must fire at least 1 alert
# "benign_log" must fire exactly 0 alerts
TEST_CASES = [
    {
        "rule_id": "CTD-001",
        "technique": "T1078",
        "attack_log": "t1078_attack.json",
        "benign_log": "benign_activity.json",
    },
    {
        "rule_id": "CTD-002",
        "technique": "T1530",
        "attack_log": "t1530_attack.json",
        "benign_log": "benign_activity.json",
    },
    {
        "rule_id": "CTD-003",
        "technique": "T1548",
        "attack_log": "t1548_attack.json",
        "benign_log": "benign_activity.json",
    },
    {
        "rule_id": "CTD-004",
        "technique": "T1110",
        "attack_log": "t1110_attack.json",
        "benign_log": "t1110_benign.json",
    },
    {
        "rule_id": "CTD-005",
        "technique": "T1087",
        "attack_log": "t1087_attack.json",
        "benign_log": "t1087_benign.json",
    },
    {
        "rule_id": "CTD-006",
        "technique": "T1562",
        "attack_log": "t1562_attack.json",
        "benign_log": "t1562_benign.json",
    },
]


def run_tests():
    passed = 0
    failed = 0
    results = []

    print("=" * 60)
    print("  Cloud-Trail-Detector — Rule Validation Test Suite")
    print("=" * 60)

    for test in TEST_CASES:
        rule_id = test["rule_id"]
        technique = test["technique"]
        rule_passed = True
        failures = []

        # --- Test 1: Attack log should fire alerts ---
        attack_path = os.path.join(TEST_LOGS_DIR, test["attack_log"])
        attack_alerts = run_detection(RULES_DIR, attack_path)

        # Filter to only alerts from this specific rule
        rule_alerts = [a for a in attack_alerts if a["rule_id"] == rule_id]

        if len(rule_alerts) == 0:
            rule_passed = False
            failures.append(f"FAIL: {test['attack_log']} — expected alerts, got 0")

        # --- Test 2: Benign log should NOT fire alerts from this rule ---
        benign_path = os.path.join(TEST_LOGS_DIR, test["benign_log"])
        benign_alerts = run_detection(RULES_DIR, benign_path)
        rule_benign_alerts = [a for a in benign_alerts if a["rule_id"] == rule_id]

        if len(rule_benign_alerts) > 0:
            rule_passed = False
            failures.append(
                f"FAIL: {test['benign_log']} — expected 0 alerts, got {len(rule_benign_alerts)}"
            )

        # Record result
        status = "PASS" if rule_passed else "FAIL"
        results.append((rule_id, technique, status, failures))

        if rule_passed:
            passed += 1
        else:
            failed += 1

    # Print results table
    print(f"\n  {'Rule':<10} {'Technique':<10} {'Status'}")
    print(f"  {'-'*10} {'-'*10} {'-'*10}")
    for rule_id, technique, status, failures in results:
        icon = "✅" if status == "PASS" else "❌"
        print(f"  {rule_id:<10} {technique:<10} {icon}  {status}")
        for failure in failures:
            print(f"             ↳ {failure}")

    print(f"\n  Results: {passed} passed, {failed} failed")
    print("=" * 60)

    # Exit code — CI reads this
    if failed > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    run_tests()