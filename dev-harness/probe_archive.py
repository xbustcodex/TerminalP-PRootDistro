"""Raw archive metadata for the hardlink cases, plus provenance of the hit."""

import os
import sys
import tarfile

ARTIFACT = sys.argv[1]
ROOT = sys.argv[2] if len(sys.argv) > 2 else ""

WANTED = {
    "usr/bin/perl5.36.0",
    "usr/bin/perl",
    "usr/bin/perlthanks",
    "usr/bin/perlbug",
    "usr/bin/uncompress",
    "usr/bin/gunzip",
    "bin",
    "gunzip",
}

TYPE_NAMES = {b"0": "REG", b"1": "LNK", b"2": "SYM", b"3": "CHR",
              b"4": "BLK", b"5": "DIR", b"6": "FIFO"}

print("--- raw tar headers for the hardlink cases ---")
found = {}
with tarfile.open(ARTIFACT, "r:*") as tf:
    for m in tf:
        if m.name in WANTED:
            found[m.name] = m
            print("  name=%-22s type=%-4s mode=%-6s linkname=%r uid=%d gid=%d"
                  % (m.name, TYPE_NAMES.get(m.type, m.type), oct(m.mode),
                     m.linkname, m.uid, m.gid))

print("--- link entry vs its target ---")
pairs = [("usr/bin/perl5.36.0", "usr/bin/perl"),
         ("usr/bin/perlthanks", "usr/bin/perlbug"),
         ("usr/bin/uncompress", "bin/gunzip")]
for link, target in pairs:
    a = found.get(link)
    b = found.get(target)
    if a is None or b is None:
        print("  %-22s or %-18s missing from archive" % (link, target))
        continue
    print("  %-22s mode=%s  ->  %-18s mode=%s   modes_agree=%s"
          % (link, oct(a.mode), target, oct(b.mode) if b else "?", a.mode == b.mode))

if ROOT:
    print("--- locating the /data/data/com.termux hit in the installed tree ---")
    needle = b"/data/data/com.termux"
    hits = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            try:
                if os.path.getsize(full) > 8 * 1024 * 1024:
                    continue
                with open(full, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            if needle in data:
                index = data.find(needle)
                hits.append((os.path.relpath(full, ROOT),
                             data[max(0, index - 70):index + 90]))
    for rel, excerpt in hits:
        print("  file: %s" % rel)
        print("    ...%s..." % excerpt.decode("utf-8", "replace").replace("\n", "\\n"))
    print("  total=%d" % len(hits))
