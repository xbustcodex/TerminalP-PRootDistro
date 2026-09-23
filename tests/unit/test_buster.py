import argparse
import errno
import io
import os
import stat
import tarfile

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
    root = tmp_path / "releases" / "0.3.2" / "rootfs"
    bindings = buster._launcher_bindings(
        tmp_path / "tmp", tmp_path / "run",
        tmp_path / "root", tmp_path / "home")
    argv = buster._launcher_argv(root, bindings)

    assert "-0" in argv
    assert f"--rootfs={root}" in argv
    # Android refuses link(2); proot must translate for the guest
    assert "--link2symlink" in argv
    assert "--cwd=/root" in argv
    # Fake root and no Android privilege bridge
    assert "--bind=/data" not in argv
    for binding in bindings:
        assert f"--bind={binding}" in argv
    assert all(arg.startswith("--") or arg == "-0" for arg in argv)
