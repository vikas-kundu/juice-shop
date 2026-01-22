#!/bin/bash
# Detect SQL injection attempts
echo "=== SQL Injection Detection ==="
echo ""
grep -iE "(union|select|insert|update|delete|drop|'--|;--|or\s+1\s*=\s*1)" /var/log/nginx/access.log 2>/dev/null | tail -20
echo ""
echo "Total SQLi attempts: $(grep -ciE "(union|select|'--|;--)" /var/log/nginx/access.log 2>/dev/null || echo 0)"
