import argparse
import contextlib
import errno
import io
import json
import os
import re
import shutil
import stat
import tempfile
import tarfile
from pathlib import Path

import pytest

from proot_distro.commands import buster


def make_archive(path, members):
    with tarfile.open(path, "w") as archive:
        for spec in members:
            info = tarfile.TarInfo(spec["name"])
            info.type = {
                "file": tarfile.REGTYPE,
                "dir": tarfile.DIRTYPE,
                "symlink": tarfile.SYMTYPE,
                "hardlink": tarfile.LNKTYPE,
                "fifo": tarfile.FIFOTYPE,
                "blk": tarfile.BLKTYPE,
                "chr": tarfile.CHRTYPE,
            }[spec.get("type", "file")]
            info.mode = spec.get("mode", 0o755 if info.isdir() else 0o644)
            info.mtime = spec.get("mtime", 1234)
            if info.issym() or info.islnk():
                info.linkname = spec["linkname"]
                archive.addfile(info)
            elif info.isreg():
                data = spec.get("data", b"")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            else:
                archive.addfile(info)


def valid_rootfs_members():
    """A representative merged-/usr rootfs, in deliberately awkward order.

    Every hardlink entry names a regular file that appears *later* in the
    archive, and ``usr/bin/uncompress`` reaches its target only after the
    ``bin -> usr/bin`` symlink is resolved, which is exactly the canonical
    Buster v0.3.2 shape. GNU tar records a hardlink member with the linked
    file's own metadata, so each link entry carries its target's mode.
    """
    return [
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
        # The real Buster v0.3.2 tarball records 0777 on every LNK header
        # while the linked file's own header carries the true mode. These
        # entries reproduce that exactly, so the tests fail if the link
        # header's mode is ever believed instead of the target's.
        {"name": "usr/bin/perl5.36.0", "type": "hardlink",
         "linkname": "./usr/bin/perl", "mode": 0o777},
        {"name": "usr/bin/perlthanks", "type": "hardlink",
         "linkname": "./usr/bin/perlbug", "mode": 0o777},
        {"name": "usr/bin/uncompress", "type": "hardlink",
         "linkname": "./bin/gunzip", "mode": 0o777},
        {"name": "usr/lib/data-alias", "type": "hardlink",
         "linkname": "./usr/lib/data", "mode": 0o777},
        {"name": "bin", "type": "symlink", "linkname": "usr/bin"},
        {"name": "sbin", "type": "symlink", "linkname": "usr/sbin"},
        {"name": "lib", "type": "symlink", "linkname": "usr/lib"},
        {"name": "usr/bin/perl", "type": "file", "data": b"perl",
         "mode": 0o755},
        {"name": "usr/bin/perlbug", "type": "file", "data": b"bug",
         "mode": 0o755},
        {"name": "usr/bin/gunzip", "type": "file", "data": b"gunzip",
         "mode": 0o755},
        {"name": "usr/lib/data", "type": "file", "data": b"data",
         "mode": 0o640},
        {"name": "usr/bin/not-executable", "type": "file", "data": b"no",
         "mode": 0o640},
    ]


def test_materializes_order_independent_hardlink_graph(tmp_path, monkeypatch):
    archive = tmp_path / "buster.tar"
    root = tmp_path / "rootfs"
    make_archive(archive, valid_rootfs_members())
    monkeypatch.setattr(buster, "_probe_hardlinks", lambda _root: False)

    assert buster._extract(archive, root) is False

    # merged-/usr aliases survive as symlinks, not as copied trees
    assert os.readlink(root / "bin") == "usr/bin"
    assert os.readlink(root / "sbin") == "usr/sbin"
    assert os.readlink(root / "lib") == "usr/lib"

    # The three canonical Buster v0.3.2 cases, after fallback materialization
    assert (root / "usr/bin/perl5.36.0").read_bytes() == b"perl"
    assert (root / "usr/bin/perlthanks").read_bytes() == b"bug"
    # "uncompress" resolves through bin -> usr/bin before materializing
    assert (root / "usr/bin/uncompress").read_bytes() == b"gunzip"

    # A materialized hardlink inherits the *target's* metadata, never the
    # 0777 the LNK header claims for itself, and never a mode guessed from
    # the file name. Widening them would hand every Debian hardlink an
    # executable, world-writable mode the Linux rootfs never had.
    assert stat.S_IMODE(os.stat(root / "usr/bin/perl5.36.0").st_mode) == 0o755
    assert stat.S_IMODE(os.stat(root / "usr/bin/uncompress").st_mode) == 0o755
    assert stat.S_IMODE(os.stat(root / "usr/lib/data-alias").st_mode) == 0o640
    assert stat.S_IMODE(os.stat(root / "usr/bin/not-executable").st_mode) == 0o640

    # Materialization means independent files, not shared inodes
    assert not os.path.samefile(root / "usr/bin/perl5.36.0", root / "usr/bin/perl")
    assert not os.path.samefile(root / "usr/bin/uncompress", root / "usr/bin/gunzip")
    assert stat.S_IMODE(os.stat(root / "tmp").st_mode) == 0o1777


def test_native_hardlink_probe_is_used_when_available(tmp_path, monkeypatch):
    archive = tmp_path / "buster.tar"
    root = tmp_path / "rootfs"
    make_archive(archive, valid_rootfs_members())
    monkeypatch.setattr(buster, "_probe_hardlinks", lambda _root: True)

    assert buster._extract(archive, root) is True
    assert os.path.samefile(root / "usr/bin/perl5.36.0", root / "usr/bin/perl")
    assert os.path.samefile(root / "usr/bin/uncompress", root / "usr/bin/gunzip")


def test_hardlink_capability_probe_reflects_the_real_filesystem(tmp_path):
    """The probe must report what the target filesystem actually does.

    This is the test that distinguishes a Linux build host from the
    TerminalP device: the same assertion is true on both, but the answer it
    observes is ``True`` on a filesystem with link(2) and ``False`` on
    Android app-private data, where the interpreter has no ``os.link``.
    """
    root = tmp_path / "probe-root"
    root.mkdir()
    link_fn = getattr(os, "link", None)
    expected = False
    if link_fn is not None:
        source = root / "source"
        source.write_bytes(b"probe")
        try:
            link_fn(source, root / "target")
            expected = True
        except OSError as exc:
            if exc.errno != errno.EPERM:
                raise
        source.unlink()
        if expected:
            (root / "target").unlink()
    assert buster._probe_hardlinks(root) is expected
    # The probe leaves nothing behind in the rootfs it tested
    assert os.listdir(root) == []


def test_hardlink_chain_resolves_through_another_hardlink(tmp_path, monkeypatch):
    """a -> b -> regular, plus a link whose target is written last."""
    archive = tmp_path / "chain.tar"
    root = tmp_path / "rootfs"
    make_archive(archive, [
        {"name": "a", "type": "hardlink", "linkname": "b", "mode": 0o755},
        {"name": "b", "type": "hardlink", "linkname": "c", "mode": 0o755},
        {"name": "c", "type": "file", "data": b"deep", "mode": 0o755},
    ])
    monkeypatch.setattr(buster, "_probe_hardlinks", lambda _root: False)

    buster._extract(archive, root)
    assert (root / "a").read_bytes() == b"deep"
    assert (root / "b").read_bytes() == b"deep"
    # The chain's 0777 headers must not survive to the installed tree
    assert stat.S_IMODE(os.stat(root / "a").st_mode) == 0o755
    assert stat.S_IMODE(os.stat(root / "b").st_mode) == 0o755


def test_hardlink_before_its_target_is_resolved_from_the_archive(
        tmp_path, monkeypatch):
    """Order independence, stated as a test rather than a hope."""
    archive = tmp_path / "reordered.tar"
    root = tmp_path / "rootfs"
    members = valid_rootfs_members()
    # Move every regular file to the very end, so every hardlink is listed
    # before the bytes it needs exist instead of merely before its header.
    regular = [m for m in members if m.get("type", "file") == "file"]
    rest = [m for m in members if m.get("type", "file") != "file"]
    make_archive(archive, rest + regular)
    monkeypatch.setattr(buster, "_probe_hardlinks", lambda _root: False)

    buster._extract(archive, root)
    assert (root / "usr/bin/perl5.36.0").read_bytes() == b"perl"
    assert (root / "usr/bin/uncompress").read_bytes() == b"gunzip"


def test_missing_os_link_makes_hardlinks_unavailable(tmp_path, monkeypatch):
    """Android CPython has no os.link; that is a capability answer, not a crash."""
    monkeypatch.setattr(buster, "_link_fn", None)
    root = tmp_path / "rootfs"
    root.mkdir()
    assert buster._probe_hardlinks(root) is False
    assert (root / ".hardlink-probe").exists() is False

    archive = tmp_path / "buster.tar"
    make_archive(archive, valid_rootfs_members())
    monkeypatch.setattr(buster, "_probe_hardlinks", lambda _root: True)
    assert buster._extract(archive, root / "out") is False
    assert (root / "out/usr/bin/perl5.36.0").read_bytes() == b"perl"


@pytest.mark.parametrize("members", [
    [{"name": "../escape", "type": "file", "data": b"x"}],
    [{"name": "a/../../escape", "type": "file", "data": b"x"}],
    [{"name": "/absolute", "type": "file", "data": b"x"}],
    [{"name": "link", "type": "symlink", "linkname": "../../outside"}],
    [{"name": "link", "type": "symlink", "linkname": "/../../outside"}],
    [{"name": "link", "type": "hardlink", "linkname": "../../outside"}],
    [{"name": "link", "type": "hardlink", "linkname": "/outside"}],
    [{"name": "dev/fifo", "type": "fifo"}],
    [{"name": "dev/sda", "type": "blk", "devmajor": 8, "devminor": 0}],
    # A hardlink whose target is not a regular archive file is never copied
    [{"name": "link", "type": "hardlink", "linkname": "dir"},
     {"name": "dir", "type": "dir"}],
    # A hardlink naming a symlink has no bytes of its own to copy
    [{"name": "link", "type": "hardlink", "linkname": "sym"},
     {"name": "sym", "type": "symlink", "linkname": "target"},
     {"name": "target", "type": "file", "data": b"x"}],
    # Two archive names colliding on one destination is ambiguous
    [{"name": "x", "type": "file", "data": b"1"},
     {"name": "./x", "type": "file", "data": b"2"}],
])
def test_unsafe_archive_members_fail_before_writing(tmp_path, members):
    archive = tmp_path / "invalid.tar"
    root = tmp_path / "rootfs"
    root.mkdir()
    sentinel = root / "sentinel"
    sentinel.write_text("keep")
    make_archive(archive, members)

    with pytest.raises(RuntimeError):
        buster._extract(archive, root)
    assert sentinel.read_text() == "keep"
    assert not (tmp_path / "escape").exists()
    assert not os.path.exists("/outside")


def test_cyclic_symlinks_are_rejected(tmp_path):
    archive = tmp_path / "symloop.tar"
    make_archive(archive, [
        {"name": "a", "type": "symlink", "linkname": "b"},
        {"name": "b", "type": "symlink", "linkname": "a"},
    ])
    with pytest.raises(RuntimeError):
        buster._extract(archive, tmp_path / "symloop-root")


def test_dangling_and_cyclic_hardlinks_are_rejected(tmp_path):
    dangling = tmp_path / "dangling.tar"
    cyclic = tmp_path / "cyclic.tar"
    make_archive(dangling, [{"name": "a", "type": "hardlink",
                             "linkname": "missing"}])
    make_archive(cyclic, [
        {"name": "a", "type": "hardlink", "linkname": "b"},
        {"name": "b", "type": "hardlink", "linkname": "a"},
    ])

    with pytest.raises(RuntimeError):
        buster._extract(dangling, tmp_path / "dangling-root")
    with pytest.raises(RuntimeError):
        buster._extract(cyclic, tmp_path / "cyclic-root")


def test_sha256_and_architecture_mapping_are_explicit():
    assert buster._ARCH_MAP["aarch64"] == "arm64"
    assert buster._ARCH_MAP["arm64"] == "arm64"
    assert buster._ARCH_MAP.get("unknown") is None
    # An unmapped device architecture fails closed instead of guessing
    assert buster._ARCH_MAP.get("mips64") is None


def test_release_metadata_is_verified_and_fails_closed(tmp_path):
    good = tmp_path / "good.json"
    good.write_text('{"version": "0.3.2", "architecture": "arm64",'
                    ' "sha256": "' + "a" * 64 + '"}')
    assert buster._load_release_metadata(str(good), "0.3.2", "arm64") == {
        "sha256": "a" * 64,
    }

    mismatch = tmp_path / "mismatch.json"
    mismatch.write_text('{"version": "0.3.1", "architecture": "arm64",'
                        ' "sha256": "' + "b" * 64 + '"}')
    with pytest.raises(RuntimeError):
        buster._load_release_metadata(str(mismatch), "0.3.2", "arm64")

    wrong_arch = tmp_path / "arch.json"
    wrong_arch.write_text('{"version": "0.3.2", "architecture": "amd64",'
                          ' "sha256": "' + "c" * 64 + '"}')
    with pytest.raises(RuntimeError):
        buster._load_release_metadata(str(wrong_arch), "0.3.2", "arm64")

    truncated = tmp_path / "truncated.json"
    truncated.write_text('{"version": "0.3.2", "architecture": "arm64",'
                         ' "sha256": "deadbeef"}')
    with pytest.raises(RuntimeError):
        buster._load_release_metadata(str(truncated), "0.3.2", "arm64")

    assert buster._load_release_metadata("", "0.3.2", "arm64") == {}


def test_release_version_cannot_escape_the_release_directory():
    for bad in ("", ".", "..", "../evil", "a/b", "a\\b", None, 7):
        with pytest.raises(RuntimeError):
            buster._validate_version(bad)
    buster._validate_version("0.3.2")


def test_active_root_requires_a_valid_recorded_release():
    assert buster._active_root({"version": "0.3.2"}).name == "rootfs"
    for bad in ({}, {"version": ""}, {"version": "../.."}, {"version": 5}):
        with pytest.raises(RuntimeError):
            buster._active_root(bad)


def test_launcher_environment_does_not_inherit_terminalp_paths(monkeypatch):
    prefix = "/data/data/com.primetech.terminal/files/usr"
    monkeypatch.setenv("PREFIX", prefix)
    monkeypatch.setenv("TERMUX_PREFIX", prefix)
    monkeypatch.setenv("HOME", "/data/data/com.primetech.terminal/files/home")
    monkeypatch.setenv("LD_LIBRARY_PATH", prefix + "/lib")
    monkeypatch.setenv("LD_PRELOAD", prefix + "/lib/libtermux-exec.so")
    monkeypatch.setenv("PYTHONPATH", prefix + "/lib/python3.14")
    monkeypatch.setenv("PYTHONHOME", prefix)
    monkeypatch.setenv("ANDROID_DATA", "/data")
    monkeypatch.setenv("PKG_CONFIG_LIBDIR", prefix + "/lib/pkgconfig")
    monkeypatch.setenv("TERMUX_APP__APP_VERSION_NAME", "0.118.3-primetech")
    env = buster._launcher_environment()

    # Buster detects its host from an identity marker, not from a path
    assert env["TERMINALP_VERSION"] == "0.118.3-primetech"

    # Sane Buster values, not TerminalP's
    assert env["HOME"] == "/root"
    assert env["PATH"].startswith("/usr/local/sbin:")
    assert "com.primetech.terminal" not in env["PATH"]
    assert "LD_LIBRARY_PATH" not in env
    assert "LD_PRELOAD" not in env
    assert "PYTHONPATH" not in env
    assert "PYTHONHOME" not in env
    assert "PREFIX" not in env
    assert "TERMUX_PREFIX" not in env
    assert "ANDROID_DATA" not in env
    assert "PKG_CONFIG_LIBDIR" not in env


def test_install_refuses_a_mismatched_architecture_before_extracting(
        tmp_path, monkeypatch):
    """aarch64 -> arm64 is the only pair this device may install.

    The refusal has to happen before the artifact is unpacked: an amd64
    rootfs must never be extracted onto an ARM64 phone and then rejected,
    and an unmapped device architecture must fail closed rather than
    falling through to whichever artifact happens to be named.
    """
    archive = tmp_path / "buster.tar"
    make_archive(archive, valid_rootfs_members())
    extracted = []
    monkeypatch.setattr(buster, "_extract",
                        lambda *a, **k: extracted.append(a) or True)

    def args_for(architecture):
        return argparse.Namespace(
            archive=str(archive), version="0.3.2",
            architecture=architecture, sha256="a" * 64,
            release_metadata=None,
        )

    monkeypatch.setattr(buster, "get_device_cpu_arch", lambda: "aarch64")
    with pytest.raises(SystemExit) as refused:
        buster._install(args_for("amd64"))
    assert refused.value.code == 1
    assert extracted == []

    # An architecture this platform has no mapping for is not guessed at
    monkeypatch.setattr(buster, "get_device_cpu_arch", lambda: "mips64")
    with pytest.raises(SystemExit) as refused:
        buster._install(args_for("arm64"))
    assert refused.value.code == 1
    assert extracted == []


def test_prepare_rootfs_gives_the_guest_a_resolver(tmp_path, monkeypatch):
    """Buster carries its own /etc/resolv.conf.

    Debian ships none -- it is normally written at boot -- and Android has
    no /etc/resolv.conf to bind in, so without this the guest has no
    resolver at all and DNS fails. Verified on the device: with this in
    place resolution and outbound HTTP work, without it they do not.
    """
    archive = tmp_path / "buster.tar"
    root = tmp_path / "rootfs"
    make_archive(archive, valid_rootfs_members())
    monkeypatch.setattr(buster, "_probe_hardlinks", lambda _root: False)
    buster._extract(archive, root)
    assert not (root / "etc" / "resolv.conf").exists()

    monkeypatch.setattr(buster, "get_device_cpu_arch", lambda: "aarch64")
    buster._prepare_rootfs(root, "arm64")

    resolver = root / "etc" / "resolv.conf"
    assert resolver.is_file() and not resolver.is_symlink()
    content = resolver.read_text()
    assert "nameserver 8.8.8.8" in content
    assert "nameserver 8.8.4.4" in content

    # The device architecture is still enforced on the staged tree
    with pytest.raises(RuntimeError):
        buster._prepare_rootfs(root, "amd64")


def test_launcher_bindings_are_an_explicit_allowlist(tmp_path):
    root = tmp_path / "persistent" / "root"
    home = tmp_path / "persistent" / "home"
    tmp = tmp_path / "persistent" / "runtime" / "tmp"
    run = tmp_path / "persistent" / "runtime" / "run"
    bindings = buster._launcher_bindings(tmp, run, root, home)

    # The kernel views and the Buster-private writable runtime directories
    assert "/dev" in bindings
    assert "/proc" in bindings
    assert "/sys" in bindings
    assert f"{tmp}:/tmp" in bindings
    assert f"{run}:/run" in bindings
    assert f"{root}:/root" in bindings
    assert f"{home}:/home" in bindings

    # No host resolver: Android has no /etc/resolv.conf, and borrowing one
    # where it does exist would tie the guest's DNS to the host
    assert not any("resolv.conf" in binding for binding in bindings)

    # Nothing from TerminalP is bound in by convenience
    for binding in bindings:
        for forbidden in ("/data", "/system", "/storage", "com.termux",
                          "/sdcard", "magisk"):
            assert forbidden not in binding, (binding, forbidden)


def test_launcher_argv_is_fake_root_inside_the_guest(tmp_path):
    bindings = buster._launcher_bindings(
        tmp_path / "tmp", tmp_path / "run",
        tmp_path / "root", tmp_path / "home")
    argv = buster._launcher_argv(bindings)

    assert "-0" in argv
    assert "--rootfs=." in argv
    # Android refuses link(2); proot must translate for the guest
    assert "--link2symlink" in argv
    assert "--cwd=/root" in argv
    # Fake root and no Android privilege bridge
    assert "--bind=/data" not in argv
    for binding in bindings:
        assert f"--bind={binding}" in argv
    assert all(arg.startswith("--") or arg == "-0" for arg in argv)


def make_active_buster(versions=("0.3.2",), *, with_buster=True, with_bash=False):
    roots = {}
    buster._ensure_state_dirs()
    for version in versions:
        root = Path(buster.RELEASES_DIR) / version / "rootfs"
        for name in ("usr", "etc", "var", "tmp", "run", "dev", "proc",
                     "sys", "home", "root", "usr/bin"):
            (root / name).mkdir(parents=True, exist_ok=True)
        if with_buster:
            command = root / "usr" / "bin" / "buster"
            command.write_text("#!/bin/sh\n", encoding="utf-8")
            command.chmod(0o755)
        if with_bash:
            shell = root / "usr" / "bin" / "bash"
            shell.write_text("#!/bin/sh\n", encoding="utf-8")
            shell.chmod(0o755)
        roots[version] = root
    with open(buster.STATE_FILE, "w", encoding="utf-8") as stream:
        json.dump({"version": versions[-1], "architecture": "arm64",
                   "state": "active", "sha256": "a" * 64}, stream)
    return roots


def exec_args(operation, *rest):
    return argparse.Namespace(buster_action="exec", archive=operation,
                              exec_args=list(rest), version=None,
                              architecture=None, sha256=None,
                              release_metadata=None)


def capture_buster_exec(monkeypatch):
    """Capture the exec the launcher performs, and stand in for the process
    replacement a real execvpe performs.

    The launcher fchdir()s into the fd-pinned rootfs and then execs. A real
    execvpe never returns, so that directory change is the process's last act.
    This mock *does* return, so putting the test process back is the mock's
    job, not the production code's: otherwise every later test in the session
    would inherit a cwd pointing into a temporary rootfs. This restores the
    test's own state only; the launcher performs no cwd restoration, and
    nothing here hides that.
    """
    seen = {}
    here = os.dup(os.open(os.curdir, os.O_RDONLY | os.O_DIRECTORY))

    def fake_execvpe(binary, argv, env):
        try:
            seen["binary"] = str(binary)
            seen["argv"] = list(argv)
            seen["env"] = dict(env)
            seen["cwd"] = os.stat(os.curdir)
        finally:
            os.fchdir(here)
        raise SystemExit(0)

    monkeypatch.setattr(os, "execvpe", fake_execvpe)
    return seen


def prepare_terminalp(monkeypatch, tmp_path):
    prefix = tmp_path / "terminalp"
    proot = prefix / "bin" / "proot"
    proot.parent.mkdir(parents=True)
    proot.write_text("proot", encoding="utf-8")
    proot.chmod(0o755)
    monkeypatch.setattr(buster, "TERMUX_PREFIX", str(prefix))
    monkeypatch.setattr(buster, "get_device_cpu_arch", lambda: "aarch64")


@pytest.mark.parametrize("tokens,expected", [
    (["status"], ["/usr/bin/buster", "exec", "status"]),
    (["services"], ["/usr/bin/buster", "exec", "services"]),
    (["capabilities"], ["/usr/bin/buster", "exec", "capabilities"]),
    (["health"], ["/usr/bin/buster", "exec", "health"]),
    (["ping"], ["/usr/bin/buster", "exec", "ping"]),
    (["present"], ["/usr/bin/buster", "exec", "present"]),
    (["service-start", "buster-runtime"],
     ["/usr/bin/buster", "exec", "service-start", "buster-runtime"]),
    (["service-restart", "event-router"],
     ["/usr/bin/buster", "exec", "service-restart", "event-router"]),
    (["service-status", "scheduler.v2_1"],
     ["/usr/bin/buster", "exec", "service-status", "scheduler.v2_1"]),
])
def test_exec_inner_exact_argv(tokens, expected):
    assert buster._exec_inner(tokens) == expected


@pytest.mark.parametrize("tokens", [
    [],
    ["start"],
    ["status", "extra"],
    # `present` names no target: any argument form is refused outright rather
    # than forwarded, so no URL, path or argv can reach the host bridge.
    ["present", "http://evil.example"],
    ["present", "http://127.0.0.1:8468"],
    ["present", "--url"],
    ["present", "buster-runtime"],
    ["present", "http://127.0.0.1:8468", "extra"],
    ["present", "-c", "am start -n com.evil/.Steal"],
    ["present-open-url"],
    ["present-url"],
    ["service-start"],
    ["service-start", "tdash", "--force"],
    ["service-start", "-tdash"],
    ["service-start", "../etc/passwd"],
    ["service-start", "tdash;rm -rf /"],
    ["service-start", "tdash$(id)"],
    ["service-start", "tdash name"],
    ["service-start", "tdash\nname"],
    ["/bin/sh"],
    ["-c", "echo unsafe"],
])
def test_exec_inner_rejects_every_unsupported_form(tokens):
    with pytest.raises(SystemExit) as refused:
        buster._exec_inner(tokens)
    assert refused.value.code == 1


def test_exec_uses_active_root_without_a_shell(tmp_path, monkeypatch):
    roots = make_active_buster(("0.3.1", "0.3.2"))
    prepare_terminalp(monkeypatch, tmp_path)
    seen = capture_buster_exec(monkeypatch)

    with pytest.raises(SystemExit) as exited:
        buster._exec(exec_args("health"))

    assert exited.value.code == 0
    argv = seen["argv"]
    assert argv[-3:] == ["/usr/bin/buster", "exec", "health"]
    assert "--rootfs=." in argv
    assert not any(token in ("/bin/bash", "/bin/sh", "sh", "-c", "-lc")
                   for token in argv)
    active_stat = os.stat(roots["0.3.2"])
    assert (seen["cwd"].st_dev, seen["cwd"].st_ino) == (
        active_stat.st_dev, active_stat.st_ino
    )
    assert str(roots["0.3.1"]) not in argv
    assert str(roots["0.3.2"]) not in argv


def test_exec_pins_the_selected_active_release(tmp_path, monkeypatch):
    roots = make_active_buster(("0.3.1", "0.3.2"))
    prepare_terminalp(monkeypatch, tmp_path)
    seen = capture_buster_exec(monkeypatch)
    active = Path(buster.RELEASES_DIR) / "0.3.2"
    original = tmp_path / "active-before-swap"
    persistent = buster._ensure_persistent

    def swap_after_pin():
        paths = persistent()
        active.rename(original)
        os.symlink(roots["0.3.1"], active, target_is_directory=True)
        return paths

    monkeypatch.setattr(buster, "_ensure_persistent", swap_after_pin)
    expected_stat = os.stat(roots["0.3.2"])

    with pytest.raises(SystemExit):
        buster._exec(exec_args("status"))

    assert (seen["cwd"].st_dev, seen["cwd"].st_ino) == (
        expected_stat.st_dev, expected_stat.st_ino
    )
    assert active.is_symlink()
    assert original.is_dir()


# -- the real-device condition: an inherited cwd the process cannot search ----
#
# TerminalP's BusterBridgeService runs inside the Android app process, which
# the platform starts with cwd=/data. The untrusted_app SELinux domain may not
# search that directory, so anything that resolves the inherited working
# directory fails with EACCES before the guest is ever reached. The launcher
# used to open os.curdir to save a cwd it could not restore anyway, because a
# successful execvpe() replaces the process image. These tests pin the real
# condition and the corrected behaviour, without touching the kernel's
# permissions: the unsearchable-ness is supplied by the test, so it is
# reproducible on any host.


@contextlib.contextmanager
def _inherited_unsearchable_cwd():
    """Yield a cwd that is inherited but can no longer be searched or reopened.

    The device's condition is not "chdir into a forbidden path": the kernel
    hands the process a cwd it is already inside, and policy then denies the
    domain `search` on it. So the directory is entered while it is still
    reachable and only then made unsearchable. From inside, the process still
    holds a valid cwd, while `open(".", O_DIRECTORY)` returns EACCES -- exactly
    what `os.open(os.curdir, ...)` did on the Pixel.

    The directory is created outside tmp_path so that denying it does not also
    break pytest's own tree cleanup, and it is removed explicitly afterwards.
    The harness holds a descriptor to its original directory, so it can return
    without ever resolving the denied path.
    """
    rescue = os.open(os.curdir, os.O_RDONLY | os.O_DIRECTORY)
    inherited = Path(tempfile.mkdtemp(prefix="inherited-cwd-"))
    try:
        os.chdir(inherited)
        inherited.chmod(0o000)   # deny search/traverse; cwd already inherited
        yield inherited
    finally:
        inherited.chmod(0o700)
        os.fchdir(rescue)
        os.close(rescue)
        shutil.rmtree(inherited, ignore_errors=True)


def test_inherited_unsearchable_cwd_really_fails_to_reopen():
    """The precondition: an inherited cwd that os.open('.') cannot open.

    This is the device's EACCES, reproduced on any host without touching
    kernel policy.
    """
    with _inherited_unsearchable_cwd():
        assert os.getcwd() is not None
        with pytest.raises(PermissionError) as denied:
            fd = os.open(os.curdir, os.O_RDONLY | os.O_DIRECTORY)
            os.close(fd)
        assert denied.value.errno == errno.EACCES


def test_exec_reaches_guest_from_an_unsearchable_inherited_cwd(
        tmp_path, monkeypatch):
    """The Android binder condition: the launcher still reaches the guest.

    This is the whole point of the fix. Under the old implementation the
    launch died at `os.open(os.curdir, ...)` with EACCES and reported
    "Buster launch refused: [Errno 13] Permission denied: '.'". Here the
    inherited cwd is equally unsearchable, and exec is still reached.
    """
    roots = make_active_buster(("0.4.0",))
    prepare_terminalp(monkeypatch, tmp_path)
    seen = capture_buster_exec(monkeypatch)

    with _inherited_unsearchable_cwd():
        assert os.getcwd()  # the kernel still reports the inherited cwd
        with pytest.raises(SystemExit) as exited:
            buster._exec(exec_args("status"))

    assert exited.value.code == 0
    assert seen["argv"][-3:] == ["/usr/bin/buster", "exec", "status"]
    active_stat = os.stat(roots["0.4.0"])
    assert (seen["cwd"].st_dev, seen["cwd"].st_ino) == (
        active_stat.st_dev, active_stat.st_ino
    )


def test_launch_does_not_depend_on_the_inherited_cwd():
    """No inherited-cwd machinery remains in the launch path.

    Checked over the parsed syntax tree rather than the raw text, so the
    comment that explains the removal cannot satisfy or break the assertion.
    """
    import ast

    tree = ast.parse(Path(buster.__file__).read_text(encoding="utf-8"))
    launch = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_launch_guest_locked"
    )
    used = {
        node.attr
        for node in ast.walk(launch)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
    }
    assert "curdir" not in used
    called = {
        node.func.attr
        for node in ast.walk(launch)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    # `os.open(os.curdir, ...)` would have shown up as the `curdir` attribute
    # above, so its absence is what proves the dependency is gone.
    assert {"fchdir", "execvpe"} <= called


def test_execvpe_failure_propagates_without_cwd_restoration(
        tmp_path, monkeypatch):
    """A launch that cannot exec still fails closed.

    The contract is no longer "the caller's cwd is restored"; it is that a
    failed launch is reported and the operation does not succeed. This asserts
    that, and that nothing swallows the OSError.
    """
    make_active_buster(("0.4.0",))
    prepare_terminalp(monkeypatch, tmp_path)

    here = os.dup(os.open(os.curdir, os.O_RDONLY | os.O_DIRECTORY))

    def failing_execvpe(binary, argv, env):
        # The launcher has already fchdir'd into the rootfs by this point, and
        # it deliberately does not put the test process back -- production no
        # longer restores a cwd. Since this mock returns, the test harness
        # owns that cleanup.
        try:
            raise OSError(errno.ENOENT, "no such file", str(binary))
        finally:
            os.fchdir(here)

    monkeypatch.setattr(os, "execvpe", failing_execvpe)

    with pytest.raises(SystemExit) as refused:
        buster._exec(exec_args("status"))

    assert refused.value.code == 1
    # Nothing escaped: the OSError was reported through the typed refusal
    # path rather than propagated or silently ignored.


@pytest.mark.parametrize("name,value", [
    ("version", "0.3.2"),
    ("architecture", "amd64"),
    ("sha256", "a" * 64),
    ("release_metadata", "/data/attacker.json"),
])
def test_exec_rejects_deployment_and_environment_override_options(name, value,
                                                                 monkeypatch):
    monkeypatch.setattr(os, "execvpe", lambda *a, **k: pytest.fail("exec"))
    args = exec_args("health")
    setattr(args, name, value)

    with pytest.raises(SystemExit) as refused:
        buster._exec(args)

    assert refused.value.code == 1


def test_exec_uses_only_environment_and_mount_allowlists(tmp_path, monkeypatch):
    make_active_buster()
    prepare_terminalp(monkeypatch, tmp_path)
    seen = capture_buster_exec(monkeypatch)
    monkeypatch.setenv("PREFIX", "/data/data/com.primetech.terminal/files/usr")
    monkeypatch.setenv("LD_PRELOAD", "/data/lib/host.so")
    monkeypatch.setenv("BUSTER_INSTALL_PATH", "/data/other")
    monkeypatch.setenv("PROOT_VERBOSE", "1")

    with pytest.raises(SystemExit):
        buster._exec(exec_args("services"))

    assert set(seen["env"]) == {
        "HOME", "PATH", "TERM", "LANG", "LC_ALL", "TERMINALP_VERSION"
    }
    binds = [arg.removeprefix("--bind=") for arg in seen["argv"]
             if arg.startswith("--bind=")]
    assert binds == ["/dev", "/proc", "/sys",
                     f"{Path(buster.PERSISTENT_DIR) / 'runtime' / 'tmp'}:/tmp",
                     f"{Path(buster.PERSISTENT_DIR) / 'runtime' / 'run'}:/run",
                     f"{Path(buster.PERSISTENT_DIR) / 'root'}:/root",
                     f"{Path(buster.PERSISTENT_DIR) / 'home'}:/home"]


@pytest.mark.parametrize("state", [
    {},
    {"version": "../escape", "architecture": "arm64"},
    {"version": "0.3.2"},
    {"version": "missing", "architecture": "arm64"},
    {"version": "0.3.2", "architecture": "amd64"},
])
def test_exec_state_failure_stops_before_private_dirs_or_exec(
        state, tmp_path, monkeypatch):
    prepare_terminalp(monkeypatch, tmp_path)
    monkeypatch.setattr(buster, "_state", lambda: state)
    called = []
    monkeypatch.setattr(buster, "_ensure_persistent",
                        lambda: called.append("persistent"))
    monkeypatch.setattr(os, "execvpe", lambda *a, **k: called.append("exec"))

    with pytest.raises(SystemExit) as refused:
        buster._exec(exec_args("health"))

    assert refused.value.code == 1
    assert called == []


def test_exec_refuses_missing_or_non_regular_guest_command(tmp_path, monkeypatch):
    make_active_buster(with_buster=False)
    prepare_terminalp(monkeypatch, tmp_path)
    monkeypatch.setattr(os, "execvpe", lambda *a, **k: pytest.fail("exec"))
    with pytest.raises(SystemExit) as refused:
        buster._exec(exec_args("health"))
    assert refused.value.code == 1

    root = Path(buster.RELEASES_DIR) / "0.3.2" / "rootfs"
    command = root / "usr" / "bin" / "buster"
    command.write_text("#!/bin/sh\n", encoding="utf-8")
    command.chmod(0o755)
    os.unlink(command)
    os.mkdir(command)
    with pytest.raises(SystemExit) as refused:
        buster._exec(exec_args("health"))
    assert refused.value.code == 1


@pytest.mark.parametrize("payload", [
    b"",
    b"[]",
    b'{"version":"../escape","architecture":"arm64"}',
    b'{"version":"missing","architecture":"arm64"}',
])
def test_exec_refuses_invalid_persisted_state_file(payload, tmp_path, monkeypatch):
    prepare_terminalp(monkeypatch, tmp_path)
    buster._ensure_state_dirs()
    with open(buster.STATE_FILE, "wb") as stream:
        stream.write(payload)
    monkeypatch.setattr(os, "execvpe", lambda *a, **k: pytest.fail("exec"))

    with pytest.raises(SystemExit) as refused:
        buster._exec(exec_args("health"))

    assert refused.value.code == 1


def test_exec_refuses_symlinked_private_bind_source(tmp_path, monkeypatch):
    make_active_buster()
    prepare_terminalp(monkeypatch, tmp_path)
    target = tmp_path / "private-target"
    target.mkdir()
    private_root = Path(buster.PERSISTENT_DIR) / "root"
    private_root.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, private_root, target_is_directory=True)
    monkeypatch.setattr(os, "execvpe", lambda *a, **k: pytest.fail("exec"))

    with pytest.raises(SystemExit) as refused:
        buster._exec(exec_args("health"))

    assert refused.value.code == 1
    assert list(target.iterdir()) == []


def test_exec_refuses_symlinked_active_release(tmp_path, monkeypatch):
    prepare_terminalp(monkeypatch, tmp_path)
    make_active_buster()
    release = Path(buster.RELEASES_DIR) / "0.3.2"
    target = tmp_path / "decoy"
    target.mkdir()
    release.rename(tmp_path / "original-release")
    os.symlink(target, release, target_is_directory=True)
    monkeypatch.setattr(os, "execvpe", lambda *a, **k: pytest.fail("exec"))

    with pytest.raises(SystemExit) as refused:
        buster._exec(exec_args("health"))
    assert refused.value.code == 1


def test_non_exec_buster_actions_reject_extra_positional_args(monkeypatch):
    called = []
    monkeypatch.setattr(buster, "_login", lambda: called.append("login"))
    args = argparse.Namespace(buster_action="login", archive=None,
                              exec_args=["unexpected"])
    with pytest.raises(SystemExit):
        buster.command_buster(args)
    assert called == []


def test_exec_adds_no_android_root_or_sudo_bridge(tmp_path, monkeypatch):
    make_active_buster()
    prepare_terminalp(monkeypatch, tmp_path)
    seen = capture_buster_exec(monkeypatch)

    with pytest.raises(SystemExit):
        buster._exec(exec_args("service-start", "buster-runtime"))

    forbidden = ("su", "sudo", "magisk", "tsu", "root", "--root-id")
    assert not any(token in forbidden for token in seen["argv"])
    assert "-0" in seen["argv"]


# --- shared service-name contract (Buster OS 0.4.2) -----------------------
#
# The guest is authoritative. This is `is_valid_service_name` copied verbatim
# out of the packaged Buster 0.4.2 exec parser
# (`opt/buster/lib/buster/exec.py`) in the ARM64 Bookworm release artifact
# sha256:e130548757bb9ca487c4423d3cc54299734e5af7e399fc85071a05554dc87361:
#
#     SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
#     SERVICE_NAME_MIN = 1
#     SERVICE_NAME_MAX = 64
#
#     def is_valid_service_name(name) -> bool:
#         if not isinstance(name, str):
#             return False
#         if not (SERVICE_NAME_MIN <= len(name) <= SERVICE_NAME_MAX):
#             return False
#         return SERVICE_NAME.fullmatch(name) is not None
#
# It is mirrored here rather than imported so the suite stays offline and
# hermetic; `test_the_host_validator_matches_the_packaged_guest_validator`
# is what proves the mirror has not drifted, and
# `test_the_host_validator_matches_the_real_packaged_artifact` re-checks the
# mirror against the actual artifact whenever one is supplied.

_GUEST_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_GUEST_SERVICE_NAME_MIN = 1
_GUEST_SERVICE_NAME_MAX = 64


def guest_is_valid_service_name(name) -> bool:
    """Verbatim mirror of the packaged Buster 0.4.2 guest validator."""
    if not isinstance(name, str):
        return False
    if not (_GUEST_SERVICE_NAME_MIN <= len(name) <= _GUEST_SERVICE_NAME_MAX):
        return False
    return _GUEST_SERVICE_NAME.fullmatch(name) is not None


# The grammar-valid names at each boundary the contract cares about, plus the
# forms a caller might try to smuggle. `separators` are inside the character
# class, so they must stay accepted: refusing them would narrow the contract
# the guest actually implements.
CONTRACT_NAMES = [
    # length 1, and the separators the grammar allows in non-leading position
    "a", "Z", "9", "runtime", "buster-runtime", "event.router_1",
    "R2D2.C-3PO_v9", "1service", "a.b-c_d", "a..b", "a--b", "a__b", "9.a-b_c",
    # length 64 -- the ceiling, which must be accepted
    "x" * 64, "a" + "b" * 62 + "c",
    "9" * 32 + "-" * 31 + "z",
    # length 65 -- one past the ceiling, which must be refused host-side
    "x" * 65, "a" + "b" * 63 + "c",
    # empty
    "",
    # leading characters outside the class
    "-runtime", ".runtime", "_runtime", "..", "---", "...",
    # path and shell syntax
    "../runtime", "runtime/child", "runtime\\child", "/runtime",
    "runtime;id", "runtime|id", "runtime&", "runtime$(id)", "runtime`id`",
    "runtime;rm -rf /", "runtime name", "runtime\nid", "runtime\tx",
    # non-strings
    None, 42, 3.5, True, ["runtime"], ("runtime",), {"runtime": 1},
]


def test_the_shared_contract_constants_are_the_guests():
    assert buster._SERVICE_NAME.pattern == _GUEST_SERVICE_NAME.pattern
    assert buster._SERVICE_NAME_MIN == _GUEST_SERVICE_NAME_MIN
    assert buster._SERVICE_NAME_MAX == _GUEST_SERVICE_NAME_MAX
    assert (buster._SERVICE_NAME_MIN, buster._SERVICE_NAME_MAX) == (1, 64)


def test_the_closed_vocabulary_is_exactly_nine_operations():
    assert set(buster._EXEC_OPERATIONS) == {
        "status", "services", "capabilities", "health", "ping", "present",
    }
    assert set(buster._SERVICE_OPERATIONS) == {
        "service-start", "service-restart", "service-status",
    }
    assert len(buster._EXEC_OPERATIONS) == 6
    assert len(buster._SERVICE_OPERATIONS) == 3
    assert not (buster._EXEC_OPERATIONS & buster._SERVICE_OPERATIONS)


@pytest.mark.parametrize("name,expected", [
    ("a", True),                                   # length 1
    ("x" * 64, True),                              # length 64, the ceiling
    ("a.b-c_d", True),                             # grammar separators
    ("R2D2.C-3PO_v9", True),
    ("a..b", True), ("a--b", True), ("a__b", True), ("9.a-b_c", True),
    ("..", False), ("---", False),                 # separators may not lead
    ("x" * 65, False),                             # length 65, over the ceiling
    ("", False),                                   # empty
    ("-runtime", False),                           # leading '-'
    (".runtime", False),
    ("../runtime", False),
    ("runtime/child", False),
    ("runtime;rm -rf /", False),                   # shell syntax
    ("runtime$(id)", False),
    ("runtime`id`", False),
    ("runtime\nid", False),
    (None, False), (42, False), (["runtime"], False),
])
def test_the_host_validator_enforces_the_shared_contract(name, expected):
    assert buster._is_valid_service_name(name) is expected


@pytest.mark.parametrize("name", CONTRACT_NAMES)
def test_the_host_validator_matches_the_packaged_guest_validator(name):
    # The whole point of the change: whatever the host accepts, the guest
    # accepts, and whatever the host refuses the guest would have refused.
    assert buster._is_valid_service_name(name) == \
        guest_is_valid_service_name(name)


def test_a_name_at_the_ceiling_reaches_the_guest_intact():
    name = "x" * 64
    for operation in ("service-start", "service-restart", "service-status"):
        assert buster._exec_inner([operation, name]) == [
            "/usr/bin/buster", "exec", operation, name,
        ]


def test_a_name_one_past_the_ceiling_is_refused_before_any_guest_process(
        monkeypatch):
    seen = capture_buster_exec(monkeypatch)
    for operation in ("service-start", "service-restart", "service-status"):
        with pytest.raises(SystemExit) as refused:
            buster._exec_inner([operation, "x" * 65])
        assert refused.value.code == 1
    assert seen == {}, "no argv was built for an over-long name"


def test_an_over_long_name_names_the_length_limit_not_the_operation(capsys):
    with pytest.raises(SystemExit):
        buster._exec_inner(["service-start", "x" * 65])
    err = capsys.readouterr().err
    assert "65 characters" in err
    assert "64" in err
    # The operation itself is supported, so it must not be reported as the
    # problem -- that would point the caller at the wrong half of the contract.
    assert "supports only" not in err


def test_the_dispatcher_still_refuses_every_unsupported_form():
    # Unchanged from v5.8.0-primetech.2: the length ceiling must not have
    # widened, narrowed or reordered anything else.
    for tokens in ([], ["start"], ["status", "extra"], ["service-start"],
                   ["service-start", "tdash", "--force"],
                   ["service-start", "-tdash"],
                   ["service-start", "../etc/passwd"],
                   ["service-start", "tdash;rm -rf /"],
                   ["service-start", "tdash$(id)"],
                   ["service-start", "tdash name"],
                   ["service-start", "tdash\nname"],
                   ["/bin/sh"], ["-c", "echo unsafe"]):
        with pytest.raises(SystemExit) as refused:
            buster._exec_inner(tokens)
        assert refused.value.code == 1, tokens


def test_the_guest_argv_is_still_constructed_and_never_caller_shaped(
        tmp_path, monkeypatch):
    make_active_buster()
    prepare_terminalp(monkeypatch, tmp_path)
    seen = capture_buster_exec(monkeypatch)

    with pytest.raises(SystemExit):
        buster._exec(exec_args("service-status", "event.router_1"))

    # The executable and the operation are fixed by this module; only the
    # grammar-validated name is the caller's, and it is a discrete argv
    # element, so it cannot become a path, a flag or a second command.
    assert seen["argv"][-4:] == [
        "/usr/bin/buster", "exec", "service-status", "event.router_1",
    ]
    # The proot binary is this module's own, at argv[0]; the caller never
    # names it.
    proot = str(Path(buster.TERMUX_PREFIX) / "bin" / "proot")
    assert seen["argv"][0] == seen["binary"] == proot
    assert "-0" in seen["argv"]
    assert "--rootfs=." in seen["argv"]
    assert seen["cwd"]  # fchdir'd onto the descriptor-pinned active root


def test_the_host_validator_matches_the_real_packaged_artifact():
    """Re-derive the guest contract from the real artifact when one is given.

    Set BUSTER_ARM64_ARTIFACT to the Buster 0.4.2 ARM64 Bookworm tarball
    (sha256:e1305487...7361) to prove that the mirror above -- and therefore
    the host validator it is compared against -- still matches the bytes that
    actually ship. Skipped when the artifact is not present so the suite stays
    hermetic offline.
    """
    import hashlib

    path = os.environ.get("BUSTER_ARM64_ARTIFACT")
    if not path or not os.path.isfile(path):
        pytest.skip("BUSTER_ARM64_ARTIFACT not set")
    expected = ("e130548757bb9ca487c4423d3cc54299734e5af7e399fc85071a"
                "05554dc87361")
    with open(path, "rb") as handle:
        blob = handle.read()
    assert hashlib.sha256(blob).hexdigest() == expected

    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        source = archive.extractfile(
            archive.getmember("opt/buster/lib/buster/exec.py")
        ).read().decode("utf-8")

    pattern = re.search(
        r'SERVICE_NAME\s*=\s*re\.compile\(r"([^"]+)"\)', source).group(1)
    assert pattern == _GUEST_SERVICE_NAME.pattern == buster._SERVICE_NAME.pattern
    assert int(re.search(
        r"SERVICE_NAME_MAX\s*=\s*(\d+)", source).group(1)) == 64
    assert buster._SERVICE_NAME_MAX == 64
