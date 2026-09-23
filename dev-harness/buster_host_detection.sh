#!/bin/bash
echo "=== test_host.py ==="
cat /opt/buster/lib/buster/tests/test_host.py

echo
echo "=== modules under /opt/buster/lib/buster ==="
find /opt/buster/lib/buster -maxdepth 2 -name '*.py' | sort | head -60

echo
echo "=== where host identity is decided ==="
grep -rn -l "terminalp\|TERMINALP\|is_termux\|host_identity" /opt/buster/lib/buster --include=*.py | head -20

echo
echo "=== the identity implementation ==="
for f in $(grep -rn -l "def host_identity\|def is_terminalp\|def is_termux" /opt/buster/lib/buster --include=*.py | head -3); do
  echo "--- $f ---"
  grep -n -B5 -A40 "def host_identity" "$f" | head -80
done
