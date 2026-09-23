#!/bin/bash
echo "=== identity marker seen inside the guest ==="
echo "TERMINALP_VERSION = [${TERMINALP_VERSION}]"
echo "PREFIX            = [${PREFIX}]  (must stay empty: a path, not identity)"

echo
echo "=== Buster host detection ==="
python3 - <<'PY'
from buster.android_integration import device
print("host_identity()      :", device.host_identity())
print("is_terminalp()       :", device.is_terminalp())
print("is_termux()          :", device.is_termux())
print("is_termux_compatible():", device.is_termux_compatible())
info = device.device_info()
print("device_info().host   :", info.host)
print("device_info().phone_host:", info.phone_host)
PY

echo
echo "=== buster doctor ==="
python3 -m buster.cli doctor 2>&1 | tail -15
echo "exit=${PIPESTATUS[0]}"

echo
echo "=== Buster's own host tests, run inside the guest ==="
cd /opt/buster/lib && python3 -m unittest buster.tests.test_host.HostDetectionTests \
  buster.tests.test_host.HostAcceptanceTests.test_doctor_accepts_terminalp \
  buster.tests.test_host.HostAcceptanceTests.test_android_capability_reports_host \
  2>&1 | tail -20
