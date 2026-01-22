# Blue Team Exercise 05: Access Control Monitoring

**Difficulty:** ⭐⭐ Intermediate  
**Time:** 20 minutes  
**Focus:** IDOR Detection, Privilege Escalation, Path Traversal

## Objective

Learn to detect access control violations including IDOR attacks, privilege escalation, and unauthorized resource access.

## Prerequisites

- Completed previous exercises
- Understanding of IDOR vulnerabilities
- Access to API logs

---

## Tasks

### Task 5.1: Detect IDOR Attempts (7 minutes)

Identify Insecure Direct Object Reference attacks:

**Common IDOR Patterns:**
- Sequential ID enumeration
- Accessing resources with different user IDs
- Same token accessing multiple user resources

**Kibana Queries:**
```
url.path:/api\/Users\/[0-9]+/
url.path:/rest\/basket\/[0-9]+/
url.path:/api\/Feedbacks\/[0-9]+/
```

**Command Line Analysis:**
```bash
# Find ID enumeration patterns
grep -E "/api/Users/[0-9]+" ./logs/nginx/access.log | \
  awk '{print $1, $7}' | sort | uniq -c | sort -rn

# Find basket access patterns
grep -E "/rest/basket/[0-9]+" ./logs/nginx/access.log | \
  awk '{print $1}' | sort | uniq -c | sort -rn

# Detect enumeration (multiple sequential IDs)
grep -E "/api/Users/[0-9]+" ./logs/nginx/access.log | \
  grep -oE "/Users/[0-9]+" | cut -d/ -f3 | sort -n | uniq -c
```

**Detection Logic:**
```
IF user_token accesses > 3 different user_ids in < 1 minute
THEN flag as IDOR_ATTEMPT
```

---

### Task 5.2: Monitor Privilege Escalation (7 minutes)

Detect attempts to access admin functionality:

**Admin Endpoints to Monitor:**
```
/administration
/api/Users (GET all users)
/api/Feedbacks (DELETE)
/api/SecurityQuestions
```

**Kibana Queries:**
```
url.path:*administration*
url.path:"/api/Users" AND http.request.method:GET
url.path:*SecurityQuestions*
http.request.method:DELETE AND url.path:*Feedbacks*
```

**Command Line:**
```bash
# Find admin panel access attempts
grep -E "/administration|/admin" ./logs/nginx/access.log

# Find attempts to list all users
grep "GET /api/Users " ./logs/nginx/access.log

# Find deletion attempts
grep "DELETE" ./logs/nginx/access.log
```

---

### Task 5.3: Path Traversal Detection (6 minutes)

Identify directory traversal attacks:

**Common Patterns:**
```
../
..%2F
..%252F
....//
%2e%2e%2f
```

**Kibana Queries:**
```
url.path:*../*
url.path:*%2e%2e*
url.query:*../*
```

**Command Line:**
```bash
# Find path traversal attempts
grep -E "(\.\./|%2e%2e|%252e)" ./logs/nginx/access.log

# Find /ftp access
grep "/ftp" ./logs/nginx/access.log

# Find null byte attempts
grep -E "%00|%2500" ./logs/nginx/access.log
```

---

## Detection Rules

### IDOR Detection Rule

```yaml
name: IDOR_Detection
description: Detect potential IDOR attacks
condition:
  - single_source_ip
  - accesses > 5 different resource_ids
  - within 2 minutes
  - same_endpoint_pattern
severity: high
action: alert
```

### Admin Access Monitoring

```yaml
name: Unauthorized_Admin_Access
description: Non-admin accessing admin endpoints
condition:
  - endpoint matches /administration|/admin
  - user_role != admin
severity: critical
action: alert + block
```

### Path Traversal Detection

```yaml
name: Path_Traversal_Attempt
description: Detect directory traversal
condition:
  - url contains "../" OR "%2e%2e"
  - any response_code
severity: high
action: alert + block
```

---

## Sensitive Resource Access

### Critical Resources to Monitor

| Resource | Sensitivity | Alert Level |
|----------|-------------|-------------|
| /ftp | High | Every access |
| /api/Users | High | Non-admin GET all |
| /encryptionkeys | Critical | Any access |
| /rest/admin/* | Critical | Non-admin access |
| *.bak files | High | Any access |

---

## Challenge: Advanced Detection

1. Can you correlate IDOR with successful data exfiltration?
2. How would you detect a user accessing another user's orders?
3. Can you identify horizontal vs. vertical privilege escalation?

---

## Baseline Normal Behavior

Understanding normal access patterns:

```bash
# Establish baseline - normal resource access patterns
# Users should only access their own basket/orders/profile

# Normal: GET /rest/basket/{own_id}
# Anomaly: GET /rest/basket/{other_id}

# Create whitelist of user->resource mappings
```

---

## Success Criteria

- [ ] Detected IDOR enumeration attempts
- [ ] Identified unauthorized admin access
- [ ] Found path traversal attempts
- [ ] Created access control monitoring rules

---

## Incident Response for Access Control

**IDOR Detected:**
1. [ ] Document accessed resources
2. [ ] Identify data potentially exposed
3. [ ] Check for actual data exfiltration
4. [ ] Block source IP
5. [ ] Review access control implementation

**Privilege Escalation:**
1. [ ] Verify if escalation was successful
2. [ ] Check for actions taken with elevated privileges
3. [ ] Audit all admin actions from session
4. [ ] Invalidate session immediately
5. [ ] Review authorization logic

---

## Notes

```
IDOR Attempts:
- Endpoints:
- Resource IDs Accessed:
- Source IPs:

Admin Access Attempts:
- Endpoints:
- Authenticated/Unauthenticated:
- Success/Failure:

Path Traversal:
- Payloads Used:
- Files Targeted:
- Success/Failure:

Rules Created:
1. 
2. 
```

---

**Next Exercise:** [Exercise 06 - Incident Response](./exercise-06-incident-response.md)
