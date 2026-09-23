"""Synthetic rootfs regression archives, run on the real Android filesystem.

Host or container extraction is not evidence for this: the defect being
covered is filesystem-specific, so every case here is built and extracted on
the device, using the shipped `_extract`, with the shipped hardlink
capability probe answering for the real target filesystem.

Validity rule under test: a malformed or hostile archive must fail *before*
activation and must not modify the active Buster installation, the staging
root, or anything else on TerminalP.
"""

import io
import os
import shutil
import stat
import sys
import tarfile
from pathlib import Path

PREFIX = "/data/data/com.primetech.terminal/files/usr"

os.environ.update({
    "TERMUX_APP__PACKAGE_NAME": "com.primetech.terminal",
    "TERMUX__PREFIX": PREFIX,
    "TERMUX__HOME": "/data/data/com.primetech.terminal/files/home",
    "TERMUX_APP__APP_VERSION_NAME": "0.118.3-primetech",
})

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proot_distro.commands import buster  # noqa: E402

WORK = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("synthetic-out")
FAILURES = []


def make_archive(path, members):
    with tarfile.open(path, "w") as archive:
        for spec in members:
            info = tarfile.TarInfo(spec["name"])
            info.type = {
                "file": tarfile.REGTYPE, "dir": tarfile.DIRTYPE,
                "symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE,
                "fifo": tarfile.FIFOTYPE, "blk": tarfile.BLKTYPE,
            }[spec.get("type", "file")]
            info.mode = spec.get("mode", 0o755 if info.isdir() else 0o644)
            info.mtime = 1234
            if info.issym() or info.islnk():
                info.linkname = spec["linkname"]
                archive.addfile(info)
            elif info.isreg():
                data = spec.get("data", b"")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            else:
                archive.addfile(info)


def check(label, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print("  [%s] %s%s" % (status, label, (" -- " + detail) if detail else ""))
    if not condition:
        FAILURES.append(label)


def mode_of(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


# ---------------------------------------------------------------- valid cases

DIRS = [
    {"name": "./", "type": "dir", "mode": 0o755},
    {"name": "etc/", "type": "dir", "mode": 0o755},
    {"name": "usr/", "type": "dir", "mode": 0o755},
    {"name": "usr/bin/", "type": "dir", "mode": 0o755},
    {"name": "usr/lib/", "type": "dir", "mode": 0o755},
    {"name": "var/", "type": "dir", "mode": 0o755},
    {"name": "tmp/", "type": "dir", "mode": 0o1777},
    {"name": "run/", "type": "dir", "mode": 0o755},
    {"name": "dev/", "type": "dir", "mode": 0o755},
    {"name": "proc/", "type": "dir", "mode": 0o555},
    {"name": "sys/", "type": "dir", "mode": 0o555},
    {"name": "home/", "type": "dir", "mode": 0o755},
    {"name": "root/", "type": "dir", "mode": 0o700},
]


def valid_members(regulars_last):
    members = list(DIRS)
    # Every LNK header carries 0777 while the linked file's own header
    # carries the true mode: exactly what the canonical v0.3.2 tarball does.
    links = [
        {"name": "usr/bin/perl5.36.0", "type": "hardlink",
         "linkname": "./usr/bin/perl", "mode": 0o777},
        {"name": "usr/bin/perlthanks", "type": "hardlink",
         "linkname": "./usr/bin/perlbug", "mode": 0o777},
        {"name": "usr/bin/uncompress", "type": "hardlink",
         "linkname": "./bin/gunzip", "mode": 0o777},
        {"name": "usr/lib/data-alias", "type": "hardlink",
         "linkname": "./usr/lib/data", "mode": 0o777},
        # hardlink -> hardlink -> regular, with the chain written backwards
        {"name": "usr/lib/chain-a", "type": "hardlink",
         "linkname": "./usr/lib/chain-b", "mode": 0o777},
        {"name": "usr/lib/chain-b", "type": "hardlink",
         "linkname": "./usr/lib/chain-c", "mode": 0o777},
    ]
    symlinks = [
        {"name": "bin", "type": "symlink", "linkname": "usr/bin"},
        {"name": "sbin", "type": "symlink", "linkname": "usr/sbin"},
        {"name": "lib", "type": "symlink", "linkname": "usr/lib"},
    ]
    regulars = [
        {"name": "usr/bin/perl", "type": "file", "data": b"perl", "mode": 0o755},
        {"name": "usr/bin/perlbug", "type": "file", "data": b"bug", "mode": 0o755},
        {"name": "usr/bin/gunzip", "type": "file", "data": b"gunzip", "mode": 0o755},
        {"name": "usr/lib/data", "type": "file", "data": b"data", "mode": 0o640},
        {"name": "usr/lib/chain-c", "type": "file", "data": b"deep", "mode": 0o750},
        {"name": "usr/bin/not-executable", "type": "file", "data": b"no",
         "mode": 0o640},
    ]
    if regulars_last:
        return members + links + symlinks + regulars
    return members + symlinks + links + regulars


def run_valid(label, regulars_last):
    print("\n=== valid archive: %s ===" % label)
    archive = WORK / ("valid-%s.tar" % label)
    root = WORK / ("valid-%s-rootfs" % label)
    if root.exists():
        shutil.rmtree(root)
    make_archive(archive, valid_members(regulars_last))

    native = buster._extract(archive, root)
    check("probe selected materialization on this filesystem",
          native is False, "native_hardlinks=%r" % native)
    check("no probe residue left behind",
          not (root / ".hardlink-probe").exists())

    check("merged-/usr bin symlink preserved",
          os.readlink(root / "bin") == "usr/bin")
    check("merged-/usr sbin symlink preserved",
          os.readlink(root / "sbin") == "usr/sbin")
    check("merged-/usr lib symlink preserved",
          os.readlink(root / "lib") == "usr/lib")

    # target appears before its hardlink
    check("perl5.36.0 -> perl, contents", 
          (root / "usr/bin/perl5.36.0").read_bytes() == b"perl")
    # hardlink reaches its target through the bin -> usr/bin symlink
    check("uncompress -> bin/gunzip, contents",
          (root / "usr/bin/uncompress").read_bytes() == b"gunzip")
    # hardlink -> hardlink -> regular
    check("chain-a -> chain-b -> chain-c, contents",
          (root / "usr/lib/chain-a").read_bytes() == b"deep")
    check("chain-b -> chain-c, contents",
          (root / "usr/lib/chain-b").read_bytes() == b"deep")

    check("perl5.36.0 inherits the target's mode, not the LNK header's",
          mode_of(root / "usr/bin/perl5.36.0") == 0o755,
          "mode=%s" % oct(mode_of(root / "usr/bin/perl5.36.0")))
    check("uncompress inherits the target's mode",
          mode_of(root / "usr/bin/uncompress") == 0o755,
          "mode=%s" % oct(mode_of(root / "usr/bin/uncompress")))
    check("non-executable hardlink stays non-executable",
          mode_of(root / "usr/lib/data-alias") == 0o640,
          "mode=%s" % oct(mode_of(root / "usr/lib/data-alias")))
    check("non-executable regular file stays non-executable",
          mode_of(root / "usr/bin/not-executable") == 0o640)
    check("executable regular file stays executable",
          mode_of(root / "usr/bin/perl") == 0o755)
    check("chain mode follows its target",
          mode_of(root / "usr/lib/chain-a") == 0o750,
          "mode=%s" % oct(mode_of(root / "usr/lib/chain-a")))
    check("sticky directory mode preserved",
          mode_of(root / "tmp") == 0o1777)

    check("materialized files are independent of their targets",
          not os.path.samefile(root / "usr/bin/perl5.36.0",
                               root / "usr/bin/perl"))
    check("materialized chain files are independent",
          not os.path.samefile(root / "usr/lib/chain-a",
                               root / "usr/lib/chain-c"))


# -------------------------------------------------------------- hostile cases

HOSTILE = {
    "../ traversal in a member name":
        [{"name": "../escape", "type": "file", "data": b"x"}],
    "traversal in the middle of a member name":
        [{"name": "a/../../escape", "type": "file", "data": b"x"}],
    "absolute member name":
        [{"name": "/absolute-escape", "type": "file", "data": b"x"}],
    "escaping symlink target":
        [{"name": "link", "type": "symlink", "linkname": "../../outside"}],
    "escaping symlink target from root":
        [{"name": "link", "type": "symlink", "linkname": "/../../outside"}],
    "escaping hardlink target":
        [{"name": "link", "type": "hardlink", "linkname": "../../outside"}],
    "absolute hardlink target":
        [{"name": "link", "type": "hardlink", "linkname": "/outside"}],
    "dangling hardlink":
        [{"name": "a", "type": "hardlink", "linkname": "missing"}],
    "cyclic hardlinks":
        [{"name": "a", "type": "hardlink", "linkname": "b"},
         {"name": "b", "type": "hardlink", "linkname": "a"}],
    "cyclic symlinks":
        [{"name": "a", "type": "symlink", "linkname": "b"},
         {"name": "b", "type": "symlink", "linkname": "a"}],
    "hardlink to a directory":
        [{"name": "link", "type": "hardlink", "linkname": "dir"},
         {"name": "dir", "type": "dir"}],
    "hardlink to a symlink":
        [{"name": "link", "type": "hardlink", "linkname": "sym"},
         {"name": "sym", "type": "symlink", "linkname": "target"},
         {"name": "target", "type": "file", "data": b"x"}],
    "device node":
        [{"name": "dev/sda", "type": "blk"}],
    "FIFO":
        [{"name": "dev/fifo", "type": "fifo"}],
    "duplicate destination":
        [{"name": "x", "type": "file", "data": b"1"},
         {"name": "./x", "type": "file", "data": b"2"}],
}


def run_hostile():
    print("\n=== hostile archives must fail closed ===")
    # A known-good active installation to prove nothing is disturbed.
    active = WORK / "active-installation"
    if active.exists():
        shutil.rmtree(active)
    active.mkdir(parents=True)
    sentinel = active / "sentinel"
    sentinel.write_text("active release")
    before = (sentinel.stat().st_size, sentinel.read_text())

    for label, members in HOSTILE.items():
        archive = WORK / "hostile.tar"
        if archive.exists():
            archive.unlink()
        make_archive(archive, members)
        staging = WORK / ("hostile-" + str(abs(hash(label))))
        if staging.exists():
            shutil.rmtree(staging)

        raised = False
        try:
            buster._extract(archive, staging)
        except RuntimeError:
            raised = True
        except Exception as exc:            # noqa: BLE001 - report precisely
            check(label, False, "wrong exception %s: %s"
                  % (type(exc).__name__, exc))
            continue

        check(label, raised, "" if raised else "extraction was NOT refused")
        check("  nothing was created outside the staging root",
              not os.path.exists("/outside")
              and not os.path.exists(str(WORK / "escape"))
              and not os.path.exists("/absolute-escape"))
        check("  the active installation is unchanged",
              (sentinel.stat().st_size, sentinel.read_text()) == before)


def main():
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    print("work dir   = %s" % WORK)
    print("os.link    = %r" % (getattr(os, "link", None) is not None))

    run_valid("targets-first", regulars_last=False)
    run_valid("hardlinks-first", regulars_last=True)
    run_hostile()

    print("\n" + "=" * 72)
    if FAILURES:
        print("FAILED CHECKS (%d):" % len(FAILURES))
        for name in FAILURES:
            print("  - %s" % name)
        sys.exit(1)
    print("all synthetic regression checks passed on the real device filesystem")


main()
