#!/bin/bash
# Detect brute force attacks
echo "=== Brute Force Detection ==="
echo ""
echo "Failed login attempts (401 responses):"
grep "/rest/user/login" /var/log/nginx/access.log 2>/dev/null | grep '" 401 ' | tail -20
echo ""
echo "Failed logins by IP:"
grep "/rest/user/login" /var/log/nginx/access.log 2>/dev/null | grep '" 401 ' | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
echo ""
TOTAL=$(grep "/rest/user/login" /var/log/nginx/access.log 2>/dev/null | grep -c '" 401 ' || echo 0)
echo "Total failed login attempts: $TOTAL"
