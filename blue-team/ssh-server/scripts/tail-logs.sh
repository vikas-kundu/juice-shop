#!/bin/bash
# View latest log entries
echo "=== Latest 50 Log Entries ==="
echo ""
tail -50 /var/log/nginx/access.log 2>/dev/null
