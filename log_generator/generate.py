"""
CloudTrail log generator
Generates simulated AWS CloudTrail JSON log files for testing detection rules.
These are NOT real AWS log - they're crafted to look like real CloudTrail output.
"""

import json
import os
from datetime import datetime, timedelta


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
        event_time = datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

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
    save_logs(generate_t1078_iam_key_creation(), "t1078_attack.json")
    save_logs(generate_t1530_s3_enumeration(), "t1530_attack.json")
    save_logs(generate_t1548_role_assumption(), "t1548_attack.json")
    save_logs(generate_benign_events(), "benign_activity.json")
    print("\nDone. All logs saved to tests/test_logs/")

if __name__ == "__main__":
    main()