#!/bin/bash
echo "=== byte-exact content of Buster's console launchers ==="
python3 - <<'PY'
for path in ("/usr/bin/buster", "/usr/bin/busterctl"):
    with open(path, "rb") as handle:
        data = handle.read()
    print("%s  (%d bytes)" % (path, len(data)))
    print("  %r" % data)
    print("  ends with newline : %s" % data.endswith(b"\n"))
    print("  has CRLF line ends: %s" % (b"\r\n" in data))
    print()
PY

echo "=== what the shell actually hands the interpreter ==="
printf 'argv seen by python: '
python3 -c 'import sys; print([repr(a) for a in sys.argv])' version

echo
echo "=== the same through the shipped launcher ==="
/usr/bin/buster version 2>&1 | head -3

echo
echo "=== confirmation: running with an explicit interpreter, no CR ==="
sh -c 'exec python3 -m buster "$@"' _ version 2>&1 | head -5
echo "exit=$?"
