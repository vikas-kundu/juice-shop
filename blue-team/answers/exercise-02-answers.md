# Exercise 02: SQL Injection Detection - ANSWERS

## Task 2.1: SQL Injection Pattern Identification

### Kibana Queries:

```kql
# Basic SQL injection detection
url.query:*OR* AND url.query:*1=1*
url.query:*UNION* AND url.query:*SELECT*
url.query:*'--*
url.query:*%27*
```

### Command Line Detection:

```bash
# Find SQL injection patterns
grep -iE "(UNION|SELECT|OR.1=1|'--|%27|%23)" ./logs/nginx/access.log

# Count SQL injection attempts
grep -ciE "(UNION|SELECT|OR.1=1)" ./logs/nginx/access.log

# Find by source IP
grep -iE "(UNION|SELECT)" ./logs/nginx/access.log | awk '{print $1}' | sort | uniq -c

# Find targeted endpoints
grep -iE "(UNION|SELECT)" ./logs/nginx/access.log | awk '{print $7}' | cut -d? -f1 | sort | uniq -c
```

### Expected SQL Injection Patterns in Logs:

```
# Auth bypass attempts
GET /rest/user/login?email='%20OR%20'1'%3D'1
POST /rest/user/login with body: {"email":"' OR 1=1--"}

# Search exploitation
GET /rest/products/search?q='))UNION%20SELECT%201,2,3,4,5,6,7,8,9--

# User enumeration
GET /rest/products/search?q='))UNION%20SELECT%20id,email,password,4,5,6,7,8,9%20FROM%20Users--
```

### Sample Detection Results:

```
SQL Injection Attempts Found:
- Count: 47 attempts
- Source IPs: 172.18.0.5, 192.168.1.100
- Targeted Endpoints: 
  - /rest/user/login (15 attempts)
  - /rest/products/search (32 attempts)
- Successful Attempts: 12 (returned 200 with large response)
```

---

## Task 2.2: Attack Payload Analysis

### Common Payloads Detected:

```bash
# Extract payloads
grep -oE "\?q=[^[:space:]]*" ./logs/nginx/access.log | \
  sed 's/?q=//' | python3 -c "import sys,urllib.parse;[print(urllib.parse.unquote(l.strip())) for l in sys.stdin]"
```

### Payload Categories:

| Category | Examples | Count |
|----------|----------|-------|
| Auth Bypass | ' OR 1=1-- | 15 |
| UNION-based | UNION SELECT | 25 |
| Blind SQLi | AND 1=1, AND 1=2 | 5 |
| Error-based | ' AND (SELECT...) | 2 |

### Success vs. Failure Analysis:

```bash
# Successful attacks (200 with SQL patterns)
grep -E "(UNION|SELECT)" ./logs/nginx/access.log | grep " 200 " | wc -l

# Failed attempts (4xx/5xx)
grep -E "(UNION|SELECT)" ./logs/nginx/access.log | grep -E " (400|401|403|500) " | wc -l

# Large responses (data exfiltration)
grep -E "(UNION|SELECT)" ./logs/nginx/access.log | awk '$10 > 5000 {print}'
```

### Data Exfiltration Indicators:

```
Requests with unusually large responses:
- GET /rest/products/search?q='))UNION... - 50KB response
- Normal search response: 2-5KB
- SQLi extraction response: 10-100KB
```

---

## Task 2.3: Detection Rules

### Regex Pattern for SQL Injection:

```regex
(?i)(\%27|\')|(\-\-)|(\%23|#)|(\%3B|;)|
(union[\s\+]+select)|
(select[\s\+]+[\*\w]+[\s\+]+from)|
(insert[\s\+]+into)|
(delete[\s\+]+from)|
(drop[\s\+]+table)|
(update[\s\+]+\w+[\s\+]+set)|
(or[\s\+]+[\d]+=[\d]+)|
(and[\s\+]+[\d]+=[\d]+)
```

### Kibana Saved Search:

**Name:** SQL Injection Detection  
**Query:**
```kql
(url.query:*UNION* AND url.query:*SELECT*) OR 
(url.query:*OR* AND url.query:*1=1*) OR 
url.query:*'--* OR 
url.query:*%27--* OR
url.query:*%3B*
```

### Elasticsearch Watcher Alert:

```json
{
  "trigger": {
    "schedule": { "interval": "1m" }
  },
  "input": {
    "search": {
      "request": {
        "indices": ["filebeat-nginx-*"],
        "body": {
          "query": {
            "bool": {
              "must": [
                { "range": { "@timestamp": { "gte": "now-5m" } } },
                { "query_string": { 
                    "query": "url.query:(*UNION* AND *SELECT*) OR url.query:(*OR* AND *1=1*)"
                  }
                }
              ]
            }
          }
        }
      }
    }
  },
  "condition": {
    "compare": { "ctx.payload.hits.total.value": { "gte": 5 } }
  },
  "actions": {
    "log_alert": {
      "logging": { "text": "SQL Injection detected! {{ctx.payload.hits.total.value}} attempts" }
    }
  }
}
```

---

## Detection Script

```python
#!/usr/bin/env python3
"""SQL Injection Detection Script"""

import re
import sys
from collections import defaultdict

SQLI_PATTERNS = [
    r"UNION\s+SELECT",
    r"OR\s+\d+=\d+",
    r"'--",
    r"%27--",
    r"SELECT\s+.*\s+FROM",
    r"INSERT\s+INTO",
    r"DELETE\s+FROM",
    r"DROP\s+TABLE",
]

def detect_sqli(log_file):
    attempts = defaultdict(list)
    
    with open(log_file) as f:
        for line in f:
            for pattern in SQLI_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    ip = line.split()[0]
                    attempts[ip].append(line.strip())
                    break
    
    print(f"Total SQL Injection Attempts: {sum(len(v) for v in attempts.values())}")
    print(f"Unique Attackers: {len(attempts)}")
    
    for ip, logs in sorted(attempts.items(), key=lambda x: -len(x[1])):
        print(f"\n{ip}: {len(logs)} attempts")
        for log in logs[:3]:
            print(f"  {log[:100]}...")

if __name__ == "__main__":
    detect_sqli(sys.argv[1] if len(sys.argv) > 1 else "./logs/nginx/access.log")
```

---

## Summary

```
SQL Injection Attempts Found:
- Count: 47
- Source IPs: 172.18.0.5, 192.168.1.100
- Targeted Endpoints:
  - /rest/user/login
  - /rest/products/search
- Successful Attempts: 12 (200 responses with large body)

Detection Rule Created:
- Pattern: UNION SELECT, OR 1=1, '--
- Threshold: 5 attempts in 5 minutes
- Action: Alert + Log + Potential Block

False Positive Considerations:
- Search queries containing "OR" naturally
- User input with apostrophes
- Technical documentation containing SQL
```
