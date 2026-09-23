"""Drive the real Buster extraction on the device and audit the result.

Runs the same code path `proot-distro buster install` runs, against the
canonical release artifact, on the real Android app-private filesystem.
"""

import hashlib
import os
import stat
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proot_distro.commands import buster  # noqa: E402

ARTIFACT = Path(sys.argv[1])
DEST = Path(sys.argv[2])
EXPECTED_SHA256 = sys.argv[3] if len(sys.argv) > 3 else ""

if EXPECTED_SHA256:
    started = time.time()
    digest = buster._hash_file(ARTIFACT)
    print("artifact sha256 = %s (%.1fs)" % (digest, time.time() - started))
    assert digest == EXPECTED_SHA256, "artifact digest mismatch"
    print("artifact digest verified against released metadata")

print("os.link present = %r" % (getattr(os, "link", None) is not None))

if DEST.exists():
    import shutil
    shutil.rmtree(DEST)
DEST.mkdir(parents=True)

print("--- capability probe on the real target filesystem ---")
probe_root = DEST / "probe"
probe_root.mkdir()
native = buster._probe_hardlinks(probe_root)
print("probe -> native hardlinks %s" % ("AVAILABLE" if native else "UNAVAILABLE"))
assert (probe_root / ".hardlink-probe").exists() is False
print("probe cleaned up after itself: True")

started = time.time()
native = buster._extract(ARTIFACT, DEST / "rootfs")
elapsed = time.time() - started
print("--- extraction ---")
print("native_hardlinks=%r elapsed=%.1fs" % (native, elapsed))
assert native is False, "expected materialization on this filesystem"

root = DEST / "rootfs"

print("--- canonical v0.3.2 hardlink cases ---")
cases = {
    "usr/bin/perl5.36.0": "usr/bin/perl",
    "usr/bin/perlthanks": "usr/bin/perlbug",
    "usr/bin/uncompress": "bin/gunzip",
}
for name, target in cases.items():
    path = root / name
    resolved = root / target
    if not resolved.exists():
        # bin -> usr/bin is a symlink; resolve the target the way the OS does
        resolved = Path(os.path.realpath(str(path.parent / os.path.basename(target))))
    assert path.is_file(), "%s missing" % name
    assert resolved.is_file(), "%s target %s missing" % (name, target)
    same_inode = os.path.samefile(path, resolved)
    size = path.stat().st_size
    mode = oct(stat.S_IMODE(path.stat().st_mode))
    with open(path, "rb") as fh:
        head = fh.read(16)
    with open(resolved, "rb") as fh:
        tail = fh.read(16)
    print("  %-22s target=%-18s size=%-10d mode=%s shared_inode=%s bytes_match=%s"
          % (name, target, size, mode, same_inode, head == tail))
    assert not same_inode, "%s should be an independent file" % name
    assert head == tail, "%s content does not match %s" % (name, target)

print("--- merged-/usr aliases ---")
for name, target in (("bin", "usr/bin"), ("sbin", "usr/sbin"), ("lib", "usr/lib")):
    link = root / name
    assert link.is_symlink(), "%s is not a symlink" % name
    assert os.readlink(link) == target, "%s -> %r" % (name, os.readlink(link))
    print("  %-6s -> %s (symlink preserved)" % (name, target))

print("--- executable / non-executable modes ---")
samples = [
    ("usr/bin/perl", 0o755),
    ("usr/bin/busybox", 0o755),
    ("etc/passwd", 0o644),
    ("etc/shadow", 0o640),
]
for rel, expected in samples:
    path = root / rel
    if not path.exists():
        print("  %-20s absent in this release" % rel)
        continue
    actual = stat.S_IMODE(path.stat().st_mode)
    print("  %-20s mode=%s expected=%s" % (rel, oct(actual), oct(expected)))

print("--- representative binaries are real ELF ---")
for rel in ("usr/bin/perl", "usr/bin/bash", "usr/bin/dpkg", "usr/bin/apt"):
    path = root / rel
    if not path.exists():
        print("  %-20s absent" % rel)
        continue
    with open(path, "rb") as fh:
        magic = fh.read(4)
    print("  %-20s exists magic=%r" % (rel, magic))
    assert magic == b"\x7fELF", "%s is not ELF" % rel

print("--- required directory tree ---")
for rel in ("usr", "etc", "var", "tmp", "run", "dev", "proc", "sys",
            "home", "root", "bin", "sbin", "lib"):
    print("  /%-6s present=%s" % (rel, os.path.lexists(root / rel)))

print("--- contamination scan: legacy Termux prefix in the installed tree ---")
legacy = b"/data/data/com.termux"
prime = b"/data/data/com.primetech.terminal"
legacy_hits = 0
prime_hits = 0
scanned = 0
for dirpath, dirnames, filenames in os.walk(root):
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
        scanned += 1
        if legacy in data:
            legacy_hits += 1
        if prime in data:
            prime_hits += 1
print("  files scanned           = %d" % scanned)
print("  legacy com.termux hits  = %d" % legacy_hits)
print("  primetech prefix hits   = %d" % prime_hits)
