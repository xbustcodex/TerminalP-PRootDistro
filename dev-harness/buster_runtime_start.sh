#!/bin/bash
# Exercise Buster OS's own runtime entry point far enough to prove the
# installed system can start its runtime architecture. Buster-side failures
# are reported separately from the TerminalP deployment result.

echo "=== how the two console scripts are wired ==="
for e in /usr/bin/buster /usr/bin/busterctl; do
  echo "--- $e ---"
  file "$e" 2>/dev/null || true
  ls -la "$e"
  if [ -L "$e" ]; then echo "  symlink -> $(readlink "$e")"; fi
  if head -1 "$e" | grep -q '^#!'; then
    echo "  shebang: $(head -1 "$e" | cat -A | head -1)"
  fi
  if grep -q $'\r' "$e" 2>/dev/null; then
    echo "  contains CR bytes: YES (line endings are CRLF)"
  else
    echo "  contains CR bytes: no"
  fi
done

echo
echo "=== buster version ==="
timeout 120 buster version 2>&1 | head -5
echo "exit=$?"

echo
echo "=== buster status (before start) ==="
timeout 180 buster status 2>&1 | head -25
echo "exit=$?"

echo
echo "=== buster doctor ==="
timeout 300 buster doctor 2>&1 | head -40
echo "exit=$?"

echo
echo "=== buster bootstrap (offline install/init) ==="
timeout 420 buster bootstrap 2>&1 | tail -30
echo "exit=$?"

echo
echo "=== buster start (bring the runtime online) ==="
timeout 300 buster start 2>&1 | tail -20
echo "exit=$?"

sleep 5
echo
echo "=== buster status (after start) ==="
timeout 180 buster status 2>&1 | head -30
echo "exit=$?"

echo
echo "=== buster caps ==="
timeout 180 buster caps 2>&1 | head -25
echo "exit=$?"

echo
echo "=== buster stop ==="
timeout 180 buster stop 2>&1 | head -15
echo "exit=$?"

echo
echo "=== bash -c with a parameter, to isolate the trailing-CR sighting ==="
bash -c 'echo "arg1=[$1]"' _ status | cat -A
