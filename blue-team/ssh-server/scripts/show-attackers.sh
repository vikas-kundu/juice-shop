#!/bin/bash
# Show unique attacker IPs
echo "=== Attacker IP Analysis ==="
echo ""
echo "Top 10 IPs by request count:"
grep "HTTP/1.1" /var/log/nginx/access.log 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
echo ""
echo "IPs with suspicious activity (401 responses):"
grep '" 401 ' /var/log/nginx/access.log 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
