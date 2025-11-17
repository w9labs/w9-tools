#!/usr/bin/env bash
echo "=== Full backend crash logs ==="
sudo journalctl -u w9 -n 100 --no-pager | tail -50

echo -e "\n=== Check database permissions ==="
ls -la /opt/w9/data/ 2>&1 || echo "data dir doesn't exist"

echo -e "\n=== Check uploads permissions ==="
ls -la /opt/w9/uploads/ 2>&1 || echo "uploads dir doesn't exist"

echo -e "\n=== Environment variables ==="
cat /etc/default/w9

echo -e "\n=== Try running backend manually to see error ==="
sudo -u w9 /opt/w9/w9 2>&1 | head -20

