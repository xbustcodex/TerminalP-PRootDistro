#!/bin/bash
# Exercise Buster OS's existing runtime/bootstrap entry point from inside the
# hosted guest. Buster-side failures are reported as Buster-side results.

echo "=== what the entry points are ==="
for e in /usr/bin/buster /usr/bin/busterctl; do
  echo "--- $e ---"
  ls -la "$e"
  head -c 120 "$e" | sed -n '1p'
done

echo
echo "=== buster python package layout ==="
ls -la /opt/buster/lib/buster | head -30

echo
echo "=== the device/host module Buster's own tests use ==="
grep -rn "^from\|^import" /opt/buster/lib/buster/tests/test_host.py 2>/dev/null | head -10

echo
echo "=== buster --help ==="
timeout 120 buster --help 2>&1 | head -30
echo "exit=$?"

echo
echo "=== buster --version ==="
timeout 120 buster --version 2>&1 | head -10
echo "exit=$?"

echo
echo "=== busterctl --help ==="
timeout 120 busterctl --help 2>&1 | head -40
echo "exit=$?"

echo
echo "=== busterctl --version ==="
timeout 120 busterctl --version 2>&1 | head -10
echo "exit=$?"

echo
echo "=== busterctl status (runtime entry point) ==="
timeout 180 busterctl status 2>&1 | head -40
echo "exit=$?"

echo
echo "=== bootstrap entry points present in the image ==="
for p in /opt/buster/bootstrap /opt/buster/bin/bootstrap /usr/bin/buster-bootstrap; do
  [ -e "$p" ] && echo "found $p"
done
find /opt/buster -maxdepth 3 -iname '*bootstrap*' -o -maxdepth 3 -iname '*setup*' 2>/dev/null | head -10
ls -la /etc/buster 2>/dev/null | head

echo
echo "=== Buster's own host-identity test, run from inside the guest ==="
cd /opt/buster/lib && timeout 180 python3 -m unittest buster.tests.test_host -v 2>&1 | tail -25
echo "exit=$?"
