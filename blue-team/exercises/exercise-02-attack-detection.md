# Blue Team Exercise 02: SQL Injection Detection

**Difficulty:** ⭐⭐ Intermediate  
**Time:** 20 minutes  
**Focus:** SQL Injection Detection, Alert Rules, Log Analysis

## Objective

Learn to detect SQL injection attacks in web application logs and create detection rules.

## Prerequisites

- Completed Exercise 01
- Kibana access configured
- Red Team may be actively attacking (or use provided attack simulation)

---

## Tasks

### Task 2.1: Identify SQL Injection Patterns (7 minutes)

Search for SQL injection indicators in logs:

**Common SQL Injection Patterns:**
```
' OR '1'='1
' OR 1=1--
UNION SELECT
'; DROP TABLE
1=1
' AND '1'='1
ORDER BY 1--
--
/**/
```

**Kibana Queries:**
```
url.query:*OR* AND url.query:*1=1*
url.query:*UNION* AND url.query:*SELECT*
url.query:*'--*
message:*SQL* OR message:*syntax*
```

**Questions to Answer:**
1. How many SQL injection attempts can you find?
2. What endpoints are being targeted?
3. What is the source IP of the attacks?

---

### Task 2.2: Analyze Attack Payloads (7 minutes)

Deep dive into specific attack payloads:

1. Find the most common SQL injection payloads used
2. Identify successful vs. failed attempts (check response codes)
3. Look for data exfiltration indicators

**Command Line Analysis:**
```bash
# Find SQL injection patterns in logs
grep -E "(UNION|SELECT|OR\+1=1|'--|\/\*)" ./logs/nginx/access.log

# Count by pattern
grep -oE "(UNION|SELECT|OR.1=1)" ./logs/nginx/access.log | sort | uniq -c

# Find successful attacks (200 responses with SQL patterns)
grep -E "(UNION|OR.1=1)" ./logs/nginx/access.log | grep " 200 "
```

---

### Task 2.3: Create Detection Rules (6 minutes)

Create custom detection rules for SQL injection:

**Basic Detection Regex:**
```regex
(\%27|\')|(\%23|#)|(\%3B|;)|(union|select|insert|update|delete|drop|alter|create|truncate)
```

**Kibana Saved Search:**
1. Navigate to Discover
2. Create a search with SQL injection patterns
3. Save as "SQL Injection Detection"

**Alert Threshold:**
- More than 5 SQL injection patterns from same IP in 5 minutes = Alert

---

## Detection Signatures

### SQL Injection Indicators

| Indicator | Description | Severity |
|-----------|-------------|----------|
| `' OR '1'='1` | Authentication bypass | Critical |
| `UNION SELECT` | Data extraction | Critical |
| `'; DROP` | Destructive injection | Critical |
| `1=1--` | Comment-based bypass | High |
| `ORDER BY 1` | Column enumeration | Medium |
| `SLEEP(` | Time-based blind | High |
| `BENCHMARK(` | MySQL time-based | High |

---

## Challenge: Advanced Detection

1. Can you detect time-based blind SQL injection?
2. Can you differentiate between automated and manual attacks?
3. What false positives might these rules generate?

---

## Success Criteria

- [ ] Identified SQL injection attempts in logs
- [ ] Documented attack source IPs
- [ ] Created at least one detection rule
- [ ] Understood successful vs. failed attempts

---

## Incident Response Checklist

When SQL injection is detected:

- [ ] Document source IP and timestamp
- [ ] Identify targeted endpoint
- [ ] Check for successful data extraction
- [ ] Block source IP (if appropriate)
- [ ] Alert application team
- [ ] Review for data breach indicators

---

## Notes

```
SQL Injection Attempts Found:
- Count: 
- Source IPs:
- Targeted Endpoints:
- Successful Attempts:

Detection Rule Created:
- Pattern:
- Threshold:
- Action:
```

---

**Next Exercise:** [Exercise 03 - XSS Detection](./exercise-03-xss-detection.md)
