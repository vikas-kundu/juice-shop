#!/bin/bash
# Real-time log monitoring
echo "=== Real-time Log Monitor ==="
echo "Press Ctrl+C to stop"
echo ""
tail -f /var/log/nginx/access.log
