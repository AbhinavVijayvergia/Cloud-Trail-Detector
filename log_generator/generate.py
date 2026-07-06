"""
CloudTrail log generator
Generates simulated AWS CloudTrail JSON log files for testing detection rules.
These are NOT real AWS log - they're crafted to look like real CloudTrail output.
"""

import json
import os
from datetime import datetime, timedelta, timezone


#Output directory for generated logs
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tests", "test_logs")

def make_event(event_source, event_name, user_name="alice", user_type="IAMUser",
               source_ip="203.0.113.50", region="us-east-1", error_code=None,
               request_params=None, response_elements=None, event_time=None):
    """
    Build a single CloudTrail event.
    This is the base template - every CloudTrail event has these fields.
    """

    if event_time is None:
        event_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": user_type,
            "principalId": "AIDACKCEVSQ6C2EXAMPLE",
            "arn": f"arn:aws:iam::123456789012:user/{user_name}",
            "accountId": "123456789012",
            "userName": user_name
        },
        "eventTime": event_time,
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": source_ip,
        "userAgent": "aws-cli/2.13.0 Python/3.10.0",
        "requestParameters": request_params or {},
        "responseElements": response_elements or {},
        "errorCode": error_code,
        "errorMessage": (
            f"User: arn:awsLiam::123456789012:user/{user_name} is not authorized"
            if error_code == "AccessDenied" else None
        )
    }
    return event

# --- Attack Scenarios ---

def generate_t1078_iam_key_creation():
    """T1078 — Valid Accounts: Attacker creates a new access key for persistence."""
    attack_event = make_event(
        event_source="iam.amazonaws.com",
        event_name="CreateAccessKey",
        user_name="compromised-user",
        source_ip="198.51.100.23",
        request_params={"userName": "compromised-user"},
        response_elements={
            "accessKey": {
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "status": "Active",
                "userName": "compromised-user"
            }
        }
    )
    return {"Records": [attack_event]}

def generate_t1530_s3_enumeration():
    """T1530 — Data from Cloud Storage: Attacker enumerates S3 buckets looking for sensitive data."""
    base_time = datetime(2026, 7, 5, 14, 0, 0)
    events = [
        # Step 1: List all buckets
        make_event(
            event_source="s3.amazonaws.com",
            event_name="ListBuckets",
            user_name="recon-user",
            source_ip="198.51.100.50",
            event_time=base_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        ),
        # Step 2: Check permissions on a bucket
        make_event(
            event_source="s3.amazonaws.com",
            event_name="GetBucketAcl",
            user_name="recon-user",
            source_ip="198.51.100.50",
            request_params={"bucketName": "company-secrets-backup"},
            event_time=(base_time + timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ),
        # Step 3: List objects in the bucket
        make_event(
            event_source="s3.amazonaws.com",
            event_name="ListObjects",
            user_name="recon-user",
            source_ip="198.51.100.50",
            request_params={"bucketName": "company-secrets-backup"},
            event_time=(base_time + timedelta(seconds=45)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ),
    ]
    return {"Records": events}

def generate_t1548_role_assumption():
    """T1548 — Abuse Elevation Control: Attacker assumes a higher-privilege role."""
    attack_event = make_event(
        event_source="sts.amazonaws.com",
        event_name="AssumeRole",
        user_name="low-privilege-user",
        source_ip="198.51.100.99",
        request_params={
            "roleArn": "arn:aws:iam::123456789012:role/AdminRole",
            "roleSessionName": "escalation-session"
        },
        response_elements={
            "credentials": {
                "accessKeyId": "ASIAIOSFODNN7EXAMPLE",
                "expiration": "2026-07-05T15:00:00Z"
            },
            "assumedRoleUser": {
                "assumedRoleId": "AROA3XFRBF23EXAMPLE:escalation-session",
                "arn": "arn:aws:sts::123456789012:assumed-role/AdminRole/escalation-session"
            }
        }
    )
    return {"Records": [attack_event]}

def generate_t1078_benign():
    """Benign: Normal EC2 and monitoring activity — no IAM key creation."""
    events = [
        make_event("ec2.amazonaws.com", "DescribeInstances",
            user_name="dev-alice", source_ip="10.0.0.10"),
        make_event("monitoring.amazonaws.com", "PutMetricData",
            user_name="monitoring-service", user_type="AWSService", source_ip="10.0.0.100"),
    ]
    return {"Records": events}


def generate_t1530_benign():
    """Benign: App server reading a specific S3 file — not enumeration."""
    event = make_event("s3.amazonaws.com", "GetObject",
        user_name="app-server", source_ip="10.0.0.25",
        request_params={"bucketName": "app-assets", "key": "logo.png"})
    return {"Records": [event]}


def generate_t1548_benign():
    """Benign: EC2 instance describing its own instance — no role assumption."""
    event = make_event("ec2.amazonaws.com", "DescribeInstances",
        user_name="app-server", source_ip="10.0.0.30")
    return {"Records": [event]}

def generate_benign_events():
    """Normal, everyday AWS activity that should NOT trigger any detection rules."""
    events = [
        # Normal EC2 usage — checking instance status
        make_event(
            event_source="ec2.amazonaws.com",
            event_name="DescribeInstances",
            user_name="dev-alice",
            source_ip="10.0.0.50"
        ),
        # Normal CloudWatch — pushing metrics
        make_event(
            event_source="monitoring.amazonaws.com",
            event_name="PutMetricData",
            user_name="monitoring-service",
            user_type="AWSService",
            source_ip="10.0.0.100"
        ),
        # Normal S3 — reading a specific known file (NOT enumerating)
        make_event(
            event_source="s3.amazonaws.com",
            event_name="GetObject",
            user_name="app-server",
            source_ip="10.0.0.25",
            request_params={"bucketName": "app-assets", "key": "logo.png"}
        ),
    ]
    return {"Records": events}

def generate_t1110_brute_force():
    """T1110 — Brute Force: Repeated failed console login attempts."""
    base_time = datetime(2026, 7, 6, 9, 0, 0)
    events = []
    # Simulate 5 failed login attempts in quick succession
    for i in range(5):
        event = make_event(
            event_source="signin.amazonaws.com",
            event_name="ConsoleLogin",
            user_name="admin",
            source_ip="198.51.100.77",
            event_time=(base_time + timedelta(seconds=i * 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        # Failed login has errorMessage set, no responseElements
        event["errorMessage"] = "Failed authentication"
        event["responseElements"] = {"ConsoleLogin": "Failure"}
        events.append(event)
    return {"Records": events}


def generate_t1110_benign():
    """Benign: Single successful console login — normal user activity."""
    event = make_event(
        event_source="signin.amazonaws.com",
        event_name="ConsoleLogin",
        user_name="dev-alice",
        source_ip="10.0.0.50"
    )
    event["errorMessage"] = None
    event["responseElements"] = {"ConsoleLogin": "Success"}
    return {"Records": [event]}


def generate_t1087_account_discovery():
    """T1087 — Account Discovery: Attacker enumerates IAM users, groups, and policies."""
    base_time = datetime(2026, 7, 6, 10, 0, 0)
    events = [
        make_event(
            event_source="iam.amazonaws.com",
            event_name="ListUsers",
            user_name="recon-user",
            source_ip="198.51.100.88",
            event_time=base_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        ),
        make_event(
            event_source="iam.amazonaws.com",
            event_name="ListGroups",
            user_name="recon-user",
            source_ip="198.51.100.88",
            event_time=(base_time + timedelta(seconds=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ),
        make_event(
            event_source="iam.amazonaws.com",
            event_name="ListPolicies",
            user_name="recon-user",
            source_ip="198.51.100.88",
            event_time=(base_time + timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ),
    ]
    return {"Records": events}


def generate_t1087_benign():
    """Benign: User checking their own info — normal, not enumeration."""
    event = make_event(
        event_source="iam.amazonaws.com",
        event_name="GetUser",
        user_name="dev-alice",
        source_ip="10.0.0.50",
        request_params={"userName": "dev-alice"}
    )
    return {"Records": [event]}


def generate_t1562_disable_cloudtrail():
    """T1562 — Impair Defenses: Attacker stops CloudTrail logging to cover tracks."""
    event = make_event(
        event_source="cloudtrail.amazonaws.com",
        event_name="StopLogging",
        user_name="attacker-user",
        source_ip="198.51.100.11",
        request_params={"name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/main-trail"}
    )
    return {"Records": [event]}


def generate_t1562_benign():
    """Benign: Admin checking CloudTrail status — reading config, not stopping it."""
    event = make_event(
        event_source="cloudtrail.amazonaws.com",
        event_name="GetTrailStatus",
        user_name="security-admin",
        source_ip="10.0.0.10",
        request_params={"name": "main-trail"}
    )
    return {"Records": [event]}

def generate_mixed_batch():
    """
    Mixed batch of 30+ events simulating a realistic stream of CloudTrail activity.
    Contains both attack events (should alert) and benign events (should NOT alert).
    Used to measure false positive rate before and after tuning.
    """
    base_time = datetime(2026, 7, 6, 8, 0, 0)
    events = []
    t = 0  # time offset in minutes

    # --- BENIGN: Normal developer activity (these should NOT fire) ---

    # Dev checking EC2 instances
    for i in range(4):
        events.append(make_event("ec2.amazonaws.com", "DescribeInstances",
            user_name="dev-alice", source_ip="10.0.0.10",
            event_time=(base_time + timedelta(minutes=t+i)).strftime("%Y-%m-%dT%H:%M:%SZ")))
    t += 5

    # App server reading from S3 (GetObject — not enumeration)
    for i in range(3):
        events.append(make_event("s3.amazonaws.com", "GetObject",
            user_name="app-server", source_ip="10.0.0.25",
            request_params={"bucketName": "app-assets", "key": f"config-{i}.json"},
            event_time=(base_time + timedelta(minutes=t+i)).strftime("%Y-%m-%dT%H:%M:%SZ")))
    t += 5

    # Monitoring service pushing metrics
    for i in range(3):
        events.append(make_event("monitoring.amazonaws.com", "PutMetricData",
            user_name="monitoring-service", user_type="AWSService", source_ip="10.0.0.100",
            event_time=(base_time + timedelta(minutes=t+i)).strftime("%Y-%m-%dT%H:%M:%SZ")))
    t += 5

    # Lambda function assuming its execution role (normal AWS behavior)
    for i in range(4):
        e = make_event("sts.amazonaws.com", "AssumeRole",
            user_name="lambda-execution-role", user_type="AWSService", source_ip="10.0.0.50",
            request_params={"roleArn": "arn:aws:iam::123456789012:role/LambdaExecRole",
                           "roleSessionName": "lambda-session"},
            event_time=(base_time + timedelta(minutes=t+i)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        events.append(e)
    t += 5

    # Admin listing users for a compliance check (known safe)
    for i in range(2):
        events.append(make_event("iam.amazonaws.com", "ListUsers",
            user_name="compliance-scanner", source_ip="10.0.0.200",
            event_time=(base_time + timedelta(minutes=t+i)).strftime("%Y-%m-%dT%H:%M:%SZ")))
    t += 5

    # Successful console logins (not failed — should not fire brute force rule)
    for i in range(3):
        e = make_event("signin.amazonaws.com", "ConsoleLogin",
            user_name=f"dev-user-{i}", source_ip="10.0.0.30",
            event_time=(base_time + timedelta(minutes=t+i)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        e["errorMessage"] = None
        e["responseElements"] = {"ConsoleLogin": "Success"}
        events.append(e)
    t += 5

    # CloudTrail status check (not disabling — should not fire)
    events.append(make_event("cloudtrail.amazonaws.com", "GetTrailStatus",
        user_name="security-admin", source_ip="10.0.0.10",
        event_time=(base_time + timedelta(minutes=t)).strftime("%Y-%m-%dT%H:%M:%SZ")))
    t += 5

    # --- ATTACK: Malicious events buried in the noise (these SHOULD fire) ---

    # T1078: Attacker creates access key
    events.append(make_event("iam.amazonaws.com", "CreateAccessKey",
        user_name="compromised-user", source_ip="198.51.100.23",
        event_time=(base_time + timedelta(minutes=t)).strftime("%Y-%m-%dT%H:%M:%SZ")))
    t += 2

    # T1530: S3 enumeration
    for name in ["ListBuckets", "GetBucketAcl", "ListObjects"]:
        events.append(make_event("s3.amazonaws.com", name,
            user_name="recon-user", source_ip="198.51.100.50",
            event_time=(base_time + timedelta(minutes=t)).strftime("%Y-%m-%dT%H:%M:%SZ")))
        t += 1

    # T1110: Failed logins (brute force)
    for i in range(3):
        e = make_event("signin.amazonaws.com", "ConsoleLogin",
            user_name="admin", source_ip="198.51.100.77",
            event_time=(base_time + timedelta(minutes=t+i)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        e["errorMessage"] = "Failed authentication"
        e["responseElements"] = {"ConsoleLogin": "Failure"}
        events.append(e)
    t += 5

    # T1562: Attacker disables CloudTrail
    events.append(make_event("cloudtrail.amazonaws.com", "StopLogging",
        user_name="attacker-user", source_ip="198.51.100.11",
        event_time=(base_time + timedelta(minutes=t)).strftime("%Y-%m-%dT%H:%M:%SZ")))

    return {"Records": events}


# --- File Output ---

def save_logs(data, filename):
    """Save log data as a JSON file."""
    filepath = os.path.join(OUTPUT_DIR, filename)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  Generated: {filepath}")

def main():
    print("Generating simulated CloudTrail logs...\n")

    # Phase 1 attack logs
    save_logs(generate_t1078_iam_key_creation(), "t1078_attack.json")
    save_logs(generate_t1530_s3_enumeration(), "t1530_attack.json")
    save_logs(generate_t1548_role_assumption(), "t1548_attack.json")

    # Phase 2 attack logs
    save_logs(generate_t1110_brute_force(), "t1110_attack.json")
    save_logs(generate_t1087_account_discovery(), "t1087_attack.json")
    save_logs(generate_t1562_disable_cloudtrail(), "t1562_attack.json")

    # Benign logs (should NOT trigger any rules)
    save_logs(generate_benign_events(), "benign_activity.json")
    save_logs(generate_t1110_benign(), "t1110_benign.json")
    save_logs(generate_t1087_benign(), "t1087_benign.json")
    save_logs(generate_t1562_benign(), "t1562_benign.json")
    save_logs(generate_t1078_benign(), "t1078_benign.json")
    save_logs(generate_t1530_benign(), "t1530_benign.json")
    save_logs(generate_t1548_benign(), "t1548_benign.json")

    save_logs(generate_mixed_batch(), "mixed_batch.json")

    print("\nDone. All logs saved to tests/test_logs/")

if __name__ == "__main__":
    main()