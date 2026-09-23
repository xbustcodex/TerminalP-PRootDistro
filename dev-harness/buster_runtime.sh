#!/bin/bash
# Exercise Buster OS's own runtime entry point from inside the hosted guest.
# A failure here is a Buster-side runtime result, reported separately from
# the TerminalP deployment result above it.

echo "=== /opt/buster layout ==="
ls -la /opt/buster
echo "--- bin ---"
ls -la /opt/buster/bin 2>/dev/null
echo "--- lib ---"
ls /opt/buster/lib 2>/dev/null

echo
echo "=== Buster python package ==="
python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/buster/lib")
try:
    import buster
    print("import buster            : OK", getattr(buster, "__file__", ""))
    print("buster.__version__       :", getattr(buster, "__version__", "(none)"))
    names = [n for n in dir(buster) if not n.startswith("_")]
    print("public names             :", ", ".join(sorted(names)[:15]))
except Exception as exc:
    print("import buster            : FAILED", type(exc).__name__, exc)
PY

echo
echo "=== host identity detection inside the guest ==="
python3 - <<'PY'
import os, sys
sys.path.insert(0, "/opt/buster/lib")
try:
    from buster import device
    print("host_identity()          :", device.host_identity())
    print("is_termux()              :", device.is_termux())
    print("PREFIX seen by Buster    :", getattr(device, "PREFIX", "(no PREFIX)"))
except Exception as exc:
    print("host identity probe      : FAILED", type(exc).__name__, exc)
PY

echo
echo "=== Buster's own entry points ==="
for candidate in /opt/buster/bin/*; do
  [ -e "$candidate" ] || continue
  echo "--- $candidate ---"
  case "$candidate" in
    *.py|*/buster|*/buster-*)
      timeout 60 "$candidate" --version 2>&1 | head -5
      echo "exit=$?"
      ;;
    *)
      echo "  (not executed: unknown entry point type)"
      ;;
  esac
done

echo
echo "=== console scripts on PATH ==="
for name in buster buster-os busterctl; do
  if command -v "$name" >/dev/null 2>&1; then
    echo "found: $(command -v "$name")"
  fi
done

echo
echo "=== Buster package metadata ==="
dpkg -l 2>/dev/null | grep -i -E "buster" | head -10
cat /opt/buster/version 2>/dev/null || true
cat /etc/buster-release 2>/dev/null || true

echo
echo "=== how package hardlinks resolved under proot (link2symlink) ==="
ls -la /usr/bin/perl /usr/bin/perl5.36.0 /usr/bin/perlthanks /usr/bin/uncompress 2>&1
echo "--- are they readable through the guest? ---"
perl5.36.0 -e 'print "perl5.36.0 executes\n"' 2>&1 | head -2
uncompress --version 2>&1 | head -2
