# Detection Rule Schema

Every `.yml` file in `rules/` must follow this structure.

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique rule ID, format: `CTD-XXX` |
| `name` | string | yes | Human-readable rule name |
| `description` | string | yes | What this rule detects and why it matters |
| `author` | string | yes | Rule author |
| `date` | string | yes | Date created (YYYY-MM-DD) |
| `severity` | string | yes | `low`, `medium`, `high`, or `critical` |
| `mitre.technique_id` | string | yes | ATT&CK technique ID (e.g., T1078) |
| `mitre.technique_name` | string | yes | ATT&CK technique name |
| `mitre.tactic` | string | yes | ATT&CK tactic (e.g., Persistence) |
| `detection.match` | object | yes | Field-value pairs to match against CloudTrail events |
| `false_positives` | list | no | Known benign scenarios that could trigger this rule |
| `references` | list | no | Links to ATT&CK page, AWS docs, etc. |

## Match Logic

- All fields inside `detection.match` must match (AND logic)
- If a field's value is a **list**, any value in the list triggers a match (OR within that field)
- **Dot notation** supported for nested fields (e.g., `userIdentity.type`)

## Example

```yaml
id: CTD-001
name: "IAM Access Key Creation"
description: "Detects when a new IAM access key is created"
author: "Abhinav Vijayvergia"
date: "2026-07-05"
severity: high

mitre:
  technique_id: "T1078"
  technique_name: "Valid Accounts"
  tactic: "Persistence"

detection:
  match:
    eventSource: "iam.amazonaws.com"
    eventName: "CreateAccessKey"

false_positives:
  - "Automated key rotation by CI/CD pipelines"
  - "Admin provisioning keys for new team members"

references:
  - "https://attack.mitre.org/techniques/T1078/"
```