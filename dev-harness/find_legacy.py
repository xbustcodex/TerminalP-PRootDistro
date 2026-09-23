"""Locate the exact files inside an installed Buster tree that mention a
legacy Termux private prefix, so the finding can be classified rather than
merely counted.
"""

import os
import sys

ROOT = sys.argv[1]
NEEDLE = sys.argv[2].encode() if len(sys.argv) > 2 else b"/data/data/com.termux"

hits = 0
for dirpath, _dirnames, filenames in os.walk(ROOT):
    for name in filenames:
        path = os.path.join(dirpath, name)
        if os.path.islink(path):
            continue
        try:
            if os.path.getsize(path) > 32 * 1024 * 1024:
                continue
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        index = data.find(NEEDLE)
        if index >= 0:
            hits += 1
            window = data[max(0, index - 120):index + 160]
            print("%s @%d\n    %r" % (path, index, window))

print("total files containing %r: %d" % (NEEDLE.decode(), hits))
