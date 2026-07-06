"""
Cloud-Trail-Detector — Detection Engine
Loads YAML detection rules and evaluates them against CloudTrail JSON logs.
"""

import json
import os
import yaml
import sys


def load_rules(rules_dir):
    """Load all YAML detection rules from the rules directory."""
    rules = []
    for filename in sorted(os.listdir(rules_dir)):
        if filename.endswith((".yml", ".yaml")):
            filepath = os.path.join(rules_dir, filename)
            with open(filepath, "r") as f:
                rule = yaml.safe_load(f)
            rule["_source_file"] = filename
            rules.append(rule)
    return rules


def load_logs(log_path):
    """Load CloudTrail JSON log file. Returns list of events from the Records array."""
    with open(log_path, "r") as f:
        data = json.load(f)
    return data.get("Records", [])


def get_nested_value(obj, dotted_key):
    """
    Get a value from a nested dict using dot notation.
    Example: get_nested_value(event, "userIdentity.userName") 
    walks into event["userIdentity"]["userName"]
    """
    keys = dotted_key.split(".")
    current = obj
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None
    return current


def event_matches_rule(event, rule):
    """
    Check if a single CloudTrail event matches a detection rule.
    All fields in the rule's match block must match (AND logic).
    If a field value is a list, any match counts (OR within that field).
    """
    match_conditions = rule.get("detection", {}).get("match", {})

    for field, expected_value in match_conditions.items():
        actual_value = get_nested_value(event, field)

        if actual_value is None:
            return False

        # If expected_value is a list, check if actual matches any item (OR)
        if isinstance(expected_value, list):
            if actual_value not in expected_value:
                return False
        else:
            # Exact match
            if actual_value != expected_value:
                return False

    return True

def load_allowlist(tuning_dir):
    """Load suppression rules from the allowlist YAML config."""
    allowlist_path = os.path.join(tuning_dir, "allowlist.yml")
    if not os.path.exists(allowlist_path):
        return {}
    with open(allowlist_path, "r") as f:
        data = yaml.safe_load(f)
    return data.get("suppressions", {})


def is_suppressed(alert, event, allowlist):
    """
    Check if an alert should be suppressed based on the allowlist.
    Returns True if the alert matches any suppression rule for its rule_id.
    """
    rule_suppressions = allowlist.get(alert["rule_id"], [])
    for suppression in rule_suppressions:
        conditions = suppression.get("conditions", {})
        # All conditions must match for suppression to apply
        match = all(
            get_nested_value(event, field) == value
            for field, value in conditions.items()
        )
        if match:
            return True
    return False

def run_detection(rules_dir, log_path, allowlist=None):
    """
    Run all detection rules against all events in a log file.
    Optionally applies suppression rules from an allowlist.
    Returns a list of alerts (dicts with rule info and matched event).
    """
    rules = load_rules(rules_dir)
    events = load_logs(log_path)
    alerts = []

    for event in events:
        for rule in rules:
            if event_matches_rule(event, rule):
                alert = {
                    "rule_id": rule.get("id"),
                    "rule_name": rule.get("name"),
                    "severity": rule.get("severity"),
                    "technique_id": rule.get("mitre", {}).get("technique_id"),
                    "technique_name": rule.get("mitre", {}).get("technique_name"),
                    "tactic": rule.get("mitre", {}).get("tactic"),
                    "matched_event": event.get("eventName"),
                    "user": event.get("userIdentity", {}).get("userName", "unknown"),
                    "source_ip": event.get("sourceIPAddress"),
                    "event_time": event.get("eventTime"),
                    "rule_file": rule.get("_source_file"),
                }

                # Apply suppression if allowlist is provided
                if allowlist and is_suppressed(alert, event, allowlist):
                    alert["suppressed"] = True
                else:
                    alert["suppressed"] = False

                alerts.append(alert)

    return alerts

def print_alerts(alerts, log_file):
    """Print detection results in a readable format."""
    print(f"\n{'='*70}")
    print(f"  Log file: {log_file}")
    print(f"  Alerts:   {len(alerts)}")
    print(f"{'='*70}")

    if not alerts:
        print("  No detections.\n")
        return

    for alert in alerts:
        print(f"\n  [!] ALERT — {alert['rule_name']}")
        print(f"      Rule:      {alert['rule_id']} ({alert['rule_file']})")
        print(f"      Severity:  {alert['severity']}")
        print(f"      ATT&CK:    {alert['technique_id']} — {alert['technique_name']}")
        print(f"      Tactic:    {alert['tactic']}")
        print(f"      Event:     {alert['matched_event']}")
        print(f"      User:      {alert['user']}")
        print(f"      Source IP:  {alert['source_ip']}")
        print(f"      Time:      {alert['event_time']}")
    print()


def main():
    # Paths
    project_root = os.path.dirname(os.path.dirname(__file__))
    rules_dir = os.path.join(project_root, "rules")
    test_logs_dir = os.path.join(project_root, "tests", "test_logs")
    tuning_dir = os.path.join(project_root, "tuning")

    # Check paths exist
    if not os.path.isdir(rules_dir):
        print(f"Error: Rules directory not found: {rules_dir}")
        sys.exit(1)

    if not os.path.isdir(test_logs_dir):
        print(f"Error: Test logs directory not found: {test_logs_dir}")
        sys.exit(1)

    # Load rules and allowlist
    rules = load_rules(rules_dir)
    allowlist = load_allowlist(tuning_dir)

    print(f"Loaded {len(rules)} detection rules from {rules_dir}")
    print(f"Loaded allowlist: {sum(len(v) for v in allowlist.values())} suppression rules\n")
    for rule in rules:
        print(f"  [{rule['id']}] {rule['name']} — {rule['mitre']['technique_id']}")

    # Run against each log file
    total_alerts = 0
    total_suppressed = 0

    for log_filename in sorted(os.listdir(test_logs_dir)):
        if log_filename.endswith(".json"):
            log_path = os.path.join(test_logs_dir, log_filename)
            all_alerts = run_detection(rules_dir, log_path, allowlist=allowlist)

            active = [a for a in all_alerts if not a["suppressed"]]
            suppressed = [a for a in all_alerts if a["suppressed"]]

            print_alerts(active, log_filename)

            if suppressed:
                print(f"  [{len(suppressed)} alert(s) suppressed by allowlist in {log_filename}]")
                for s in suppressed:
                    print(f"    ↳ {s['rule_id']} — {s['matched_event']} by {s['user']}")
                print()

            total_alerts += len(active)
            total_suppressed += len(suppressed)

    print(f"{'='*70}")
    print(f"  Active alerts:     {total_alerts}")
    print(f"  Suppressed alerts: {total_suppressed}")
    print(f"  Total fired:       {total_alerts + total_suppressed}")
    print(f"{'='*70}")
    # Paths
    project_root = os.path.dirname(os.path.dirname(__file__))
    rules_dir = os.path.join(project_root, "rules")
    test_logs_dir = os.path.join(project_root, "tests", "test_logs")

    # Check paths exist
    if not os.path.isdir(rules_dir):
        print(f"Error: Rules directory not found: {rules_dir}")
        sys.exit(1)

    if not os.path.isdir(test_logs_dir):
        print(f"Error: Test logs directory not found: {test_logs_dir}")
        sys.exit(1)

    # Load rules once
    rules = load_rules(rules_dir)
    print(f"Loaded {len(rules)} detection rules from {rules_dir}\n")
    for rule in rules:
        print(f"  [{rule['id']}] {rule['name']} — {rule['mitre']['technique_id']}")

    # Run against each log file
    total_alerts = 0
    for log_filename in sorted(os.listdir(test_logs_dir)):
        if log_filename.endswith(".json"):
            log_path = os.path.join(test_logs_dir, log_filename)
            alerts = run_detection(rules_dir, log_path)
            print_alerts(alerts, log_filename)
            total_alerts += len(alerts)

    print(f"{'='*70}")
    print(f"  Total alerts across all logs: {total_alerts}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()