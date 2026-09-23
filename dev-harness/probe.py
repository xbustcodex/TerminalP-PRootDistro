"""Device-side facts: artifact identity, archive shape, POSIX surface."""

import errno
import hashlib
import os
import stat
import sys
import tarfile

HOME = os.environ["HOME"]
ARTIFACT = (sys.argv[1] if len(sys.argv) > 1
            else os.path.join(HOME, "buster-os-0.3.2-arm64-bookworm.tar.gz"))
WORK = os.path.join(HOME, "posix-probe")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def report(label, fn):
    try:
        print("  %-46s -> %r" % (label, fn()))
    except Exception as exc:  # noqa: BLE001 - the point is to catalogue these
        print("  %-46s -> %s: %s" % (label, type(exc).__name__, exc))


print("python=%s" % sys.version.split()[0])
print("HOME=%s" % HOME)
print("artifact size=%d" % os.path.getsize(ARTIFACT))
print("artifact sha256=%s" % sha256(ARTIFACT))

print("--- first members ---")
with tarfile.open(ARTIFACT, "r:*") as tf:
    for i, m in enumerate(tf):
        if i >= 6:
            break
        print("  %-12s type=%r link=%r mode=%o" % (m.name, m.type, m.linkname, m.mode))

os.makedirs(WORK, exist_ok=True)
src = os.path.join(WORK, "src")
with open(src, "wb") as f:
    f.write(b"probe")
dst = os.path.join(WORK, "dst")
for p in (dst,):
    try:
        os.unlink(p)
    except OSError:
        pass

print("--- os surface ---")
report("hasattr(os, 'link')", lambda: hasattr(os, "link"))
report("hasattr(os, 'symlink')", lambda: hasattr(os, "symlink"))
report("os.link(src, dst)", lambda: os.link(src, dst))
report("os.utime(follow_symlinks=False)", lambda: os.utime(
    src, (1, 1), follow_symlinks=False))
report("os.utime in supports_follow_symlinks", lambda: (
    os.utime in os.supports_follow_symlinks))
report("os.chmod in supports_follow_symlinks", lambda: (
    os.chmod in os.supports_follow_symlinks))
report("os.stat in supports_follow_symlinks", lambda: (
    os.stat in os.supports_follow_symlinks))
report("os.open in supports_dir_fd", lambda: (os.open in os.supports_dir_fd))
report("os.stat in supports_dir_fd", lambda: (os.stat in os.supports_dir_fd))
report("os.symlink in supports_dir_fd", lambda: (
    os.symlink in os.supports_dir_fd))
report("os.O_NOFOLLOW", lambda: os.O_NOFOLLOW)
report("os.O_DIRECTORY", lambda: os.O_DIRECTORY)

print("--- mode fidelity ---")
mode_file = os.path.join(WORK, "mode-file")
with open(mode_file, "wb") as f:
    f.write(b"x")
os.chmod(mode_file, 0o755)
report("chmod 0755 then st_mode", lambda: oct(
    stat.S_IMODE(os.stat(mode_file).st_mode)))
os.chmod(mode_file, 0o1777)
report("chmod 01777 then st_mode", lambda: oct(
    stat.S_IMODE(os.stat(mode_file).st_mode)))
os.chmod(mode_file, 0o640)
report("chmod 0640 then st_mode", lambda: oct(
    stat.S_IMODE(os.stat(mode_file).st_mode)))

print("--- errno for os.link when present ---")
if hasattr(os, "link"):
    try:
        os.link(src, dst)
        print("  link succeeded (hardlinks available)")
    except OSError as exc:
        print("  link failed errno=%r (%s)" % (exc.errno, errno.errorcode.get(exc.errno)))
else:
    print("  os.link missing entirely -> treat as unsupported")

print("--- existing deployment attempt ---")
legacy = os.path.join(HOME, "files/home/buster-os")
report("legacy rootfs exists", lambda: os.path.isdir(
    os.path.join(legacy, "rootfs")))
