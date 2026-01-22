# Blue Team Exercise 01: Environment Setup & Log Analysis Basics

**Difficulty:** ⭐ Beginner  
**Time:** 15 minutes  
**Focus:** SIEM Setup, Log Collection, Basic Analysis

## Objective

Set up your Blue Team monitoring environment and become familiar with the log analysis tools available.

## Prerequisites

- Docker environment running with full stack
- Access to Kibana: http://localhost:5601
- Access to logs directory: `./logs/nginx/`

---

## Tasks

### Task 1.1: Verify Log Collection (5 minutes)

Confirm that logs are being collected properly:

1. Access Kibana at http://localhost:5601
2. Navigate to Stack Management → Index Patterns
3. Create index patterns for:
   - `filebeat-nginx-*`
   - `filebeat-docker-*`
4. Verify data is flowing in Discover view

**Verification Steps:**
- Check that Nginx access logs are appearing
- Confirm Docker container logs are visible
- Note the fields available for analysis

---

### Task 1.2: Understand Log Structure (5 minutes)

Analyze the log format and identify key fields:

1. In Kibana Discover, look at a sample log entry
2. Identify the following fields:
   - Source IP address
   - Request path
   - HTTP method
   - Response status code
   - User agent
   - Timestamp

3. Look at raw nginx logs:
```bash
cat ./logs/nginx/access.log | tail -20
cat ./logs/nginx/security.log | tail -20
```

---

### Task 1.3: Basic Log Queries (5 minutes)

Practice basic log queries in Kibana:

1. Find all 404 errors
2. Find all POST requests
3. Find requests from a specific IP
4. Find requests containing "admin" in the path

**KQL Examples:**
```
response:404
http.request.method:POST
source.ip:"172.18.0.1"
url.path:*admin*
```

---

## Understanding Attack Indicators

Common log patterns that indicate attacks:

| Pattern | Possible Attack |
|---------|-----------------|
| Multiple 401/403 responses | Brute force / Auth bypass |
| SQL keywords in URL | SQL Injection |
| Script tags in parameters | XSS Attempts |
| ../.. in paths | Path Traversal |
| Unusual User-Agents | Automated scanning |
| High request rate from single IP | DoS / Scanning |

---

## Success Criteria

- [ ] Kibana is accessible and configured
- [ ] Index patterns created successfully
- [ ] Can view logs in Discover
- [ ] Understand log field structure
- [ ] Successfully ran basic queries

---

## Notes

Document your observations:

```
Log Fields Available:
- 
- 
- 

Normal Traffic Patterns:
- Average requests per minute:
- Common paths accessed:
- Common User-Agents:
```

---

**Next Exercise:** [Exercise 02 - Attack Detection](./exercise-02-attack-detection.md)
