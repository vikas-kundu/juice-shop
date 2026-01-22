# Exercise 01: Environment Setup & Log Analysis - ANSWERS

## Task 1.1: Verify Log Collection

### Kibana Index Pattern Setup:

1. Navigate to: http://localhost:5601
2. Go to **Stack Management** → **Index Patterns**
3. Click **Create index pattern**

**For Nginx Logs:**
```
Name: filebeat-nginx-*
Time field: @timestamp
```

**For Docker Logs:**
```
Name: filebeat-docker-*
Time field: @timestamp
```

### Verification Commands:

```bash
# Check Elasticsearch is receiving data
curl http://localhost:9200/_cat/indices?v

# Check for filebeat indices
curl http://localhost:9200/filebeat-*/_count

# Verify nginx logs exist
ls -la ./logs/nginx/

# View recent logs
tail -20 ./logs/nginx/access.log
```

---

## Task 1.2: Log Structure Understanding

### Key Fields in Nginx Logs:

| Field | Description | Example |
|-------|-------------|---------|
| $remote_addr | Source IP | 172.18.0.1 |
| $time_local | Timestamp | 22/Jan/2026:10:15:30 |
| $request | Full request | GET /api/Users HTTP/1.1 |
| $status | Response code | 200, 401, 404 |
| $body_bytes_sent | Response size | 1234 |
| $http_user_agent | Browser/tool | Mozilla/5.0... |
| $request_body | POST data | {"email":"..."} |

### Sample Log Entry Analysis:

```
172.18.0.1 - - [22/Jan/2026:10:15:30 +0000] "GET /rest/products/search?q=test HTTP/1.1" 200 5432 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

**Breakdown:**
- Source IP: `172.18.0.1`
- Timestamp: `22/Jan/2026:10:15:30`
- Method: `GET`
- Path: `/rest/products/search`
- Query: `q=test`
- Status: `200`
- Size: `5432` bytes
- User-Agent: `Mozilla/5.0...`

---

## Task 1.3: Basic Log Queries

### Kibana KQL Queries:

**Find all 404 errors:**
```
http.response.status_code:404
```

**Find all POST requests:**
```
http.request.method:POST
```

**Find requests from specific IP:**
```
source.ip:"172.18.0.1"
```

**Find admin-related requests:**
```
url.path:*admin*
```

**Find login attempts:**
```
url.path:"/rest/user/login"
```

### Command Line Equivalents:

```bash
# Find 404 errors
grep " 404 " ./logs/nginx/access.log | wc -l

# Find POST requests
grep "POST " ./logs/nginx/access.log | wc -l

# Find specific IP
grep "^172.18.0.1" ./logs/nginx/access.log | wc -l

# Find admin paths
grep -E "/admin|/administration" ./logs/nginx/access.log
```

---

## Expected Results

### Normal Traffic Patterns:

```
Log Fields Available:
- @timestamp
- source.ip
- url.path
- url.query
- http.request.method
- http.response.status_code
- user_agent.original
- http.response.body.bytes

Normal Traffic Patterns:
- Average requests per minute: 10-50
- Common paths accessed: /, /rest/products, /api/Products
- Common User-Agents: Chrome, Firefox, Safari

Baseline Metrics:
- 200 responses: ~80%
- 404 responses: ~5%
- 401/403 responses: ~10%
- Average response size: 2-5KB
```

---

## Kibana Dashboard Creation

### Basic Dashboard Widgets:

1. **Request Count Over Time**
   - Visualization: Line chart
   - Y-axis: Count
   - X-axis: @timestamp

2. **Top Source IPs**
   - Visualization: Data Table
   - Metric: Count
   - Bucket: Terms, source.ip

3. **Response Codes Distribution**
   - Visualization: Pie chart
   - Metric: Count
   - Bucket: Terms, http.response.status_code

4. **Top Requested Paths**
   - Visualization: Horizontal Bar
   - Metric: Count
   - Bucket: Terms, url.path

---

## Troubleshooting

### Kibana Not Showing Data:

```bash
# Check Elasticsearch health
curl http://localhost:9200/_cluster/health

# Check Filebeat status
docker logs filebeat

# Manually test log ingestion
curl -X POST http://localhost:9200/test-index/_doc \
  -H "Content-Type: application/json" \
  -d '{"message": "test log entry"}'
```

### Common Issues:

| Issue | Solution |
|-------|----------|
| No data in Kibana | Check Filebeat container logs |
| Index pattern not found | Refresh index patterns |
| Elasticsearch down | Check memory limits, vm.max_map_count |
| Logs not flowing | Verify nginx log paths |
