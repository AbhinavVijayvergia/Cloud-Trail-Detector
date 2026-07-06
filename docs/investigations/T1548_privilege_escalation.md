# T1548 — Abuse Elevation Control Mechanism (IAM Role Assumption)

## What the attack does
The attacker has a low-privilege IAM user but wants admin access. They call `sts:AssumeRole` targeting a higher-privilege role (e.g., AdminRole, PowerUserRole). If the role's trust policy allows it and the user has `sts:AssumeRole` permission, they get temporary admin credentials — typically valid for 1 hour. That's enough time to create backdoors, exfiltrate data, or escalate further.

## Why it matters
Privilege escalation turns a partial compromise into a full account takeover. STS-based escalation is subtle — it doesn't modify any user, it just borrows an existing role's permissions temporarily, leaving a smaller footprint than creating a new admin user.

## What the detection catches
- Any `AssumeRole` call via STS
- Catches both human users and services attempting role assumption

## What it might miss
- Lambda functions, EC2 instances, and other AWS services legitimately assume roles constantly — high FP rate without tuning
- After tuning: suppressed `lambda-execution-role` from internal IPs
- Chained role assumption (assume role A, then from that role assume role B) — each hop appears as a separate AssumeRole event, but correlation across hops requires more logic

## Detection confidence
Low without tuning, Medium after tuning — very noisy rule in real environments due to legitimate AWS service usage.