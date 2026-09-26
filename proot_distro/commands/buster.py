"""TerminalP hosting support for canonical Buster OS rootfs releases.

Buster is an independent Linux product. This module only provides the
existing proot-distro command path needed to install and launch its published
rootfs releases; it does not alter the release format or the Buster runtime.
"""

import errno
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tarfile
from pathlib import Path

from proot_distro.arch import get_device_cpu_arch
from proot_distro.atomic import atomic_write
from proot_distro.constants import RUNTIME_DIR, TERMUX_PREFIX
from proot_distro.locking import ContainerLock
from proot_distro.message import C, crit_error, msg
from proot_distro.helpers import rootfs as rootfs_helpers
from proot_distro import dirfd, statedir

BUSTER_DIR = os.path.join(RUNTIME_DIR, "buster")
RELEASES_DIR = os.path.join(BUSTER_DIR, "releases")
PERSISTENT_DIR = os.path.join(BUSTER_DIR, "persistent")
STATE_FILE = os.path.join(BUSTER_DIR, "state.json")

# Android/Termux names and Debian names are deliberately mapped explicitly.
_ARCH_MAP = {
    "aarch64": "arm64",
    "arm64": "arm64",
    "x86_64": "amd64",
    "amd64": "amd64",
    "arm": "armhf",
}
_MAX_LINKS = 1_000_000
_MAX_MEMBERS = 2_000_000
_MAX_SYMLINK_HOPS = 40
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024 * 1024
_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_EXEC_OPERATIONS = frozenset(
    ("status", "services", "capabilities", "health", "ping")
)
_SERVICE_OPERATIONS = frozenset(
    ("service-start", "service-restart", "service-status")
)

# TerminalP fork contract marker. TerminalP pins this literal in
# scripts/bootstrap-aarch64.manifest and PRIMETECH_PACKAGE_BUILD_CONFIG.sh and
# cross-checks it against the source it is about to build, so a payload that is
# upstream termux/proot-distro -- which has no `buster` command and therefore no
# exec dispatcher -- fails closed instead of shipping behind a PrimeTech pin.
# The marker is necessary but not sufficient: TerminalP's package contract test
# also exercises the parser and the dispatcher behaviourally, because a source
# that merely mentions this string is still not a source that accepts `exec`.
FORK_MARKER = "TERMINALP_PROOT_DISTRO_BUSTER_EXEC"

# link(2), when the interpreter has it at all. Termux/Android CPython is
# built without os.link, so the attribute is *absent* rather than failing
# at call time: asking for it raises AttributeError, which is not an
# OSError and would escape a capability probe written around errno alone.
# Verified on the TerminalP device (CPython 3.14.6, aarch64 Android).
_link_fn = getattr(os, "link", None)

# errnos that mean "this filesystem will not give this process a hardlink".
_LINK_UNSUPPORTED_ERRNOS = frozenset(
    value for value in (
        errno.EPERM, errno.EACCES, errno.EROFS,
        getattr(errno, "ENOTSUP", None), getattr(errno, "EOPNOTSUPP", None),
        getattr(errno, "EXDEV", None), getattr(errno, "EMLINK", None),
    ) if value is not None
)


def _ensure_state_dirs():
    """Create Buster's private state directories through proot-distro's state walk."""
    fd = statedir.open_state_dir(BUSTER_DIR, create=True)
    os.close(fd)
    for path in (RELEASES_DIR, PERSISTENT_DIR):
        fd = statedir.open_state_dir(path, create=True)
        os.close(fd)


def _remove_state_tree(path):
    """Remove one Buster-owned tree without following a state-tree symlink."""
    if not statedir.remove_state_tree(path):
        raise RuntimeError(f"could not remove incomplete Buster tree: {path}")


def _normalise_member_name(name: str):
    """Return strict root-relative archive components.

    A leading ``./`` is normal tar spelling. Absolute names and any ``..``
    component are rejected rather than normalised, because this archive is an
    external release artifact and must never get host-path semantics.
    """
    if not isinstance(name, str) or not name or "\x00" in name:
        raise RuntimeError("malformed archive path")
    if name.startswith("/"):
        raise RuntimeError(f"absolute archive path rejected: {name!r}")
    trimmed = name.rstrip("/")
    # A '.' component names the directory it already sits in, which is how
    # tools spell a path as './usr/bin/perl'. It is dropped rather than
    # rejected; '' (a doubled separator) and '..' still are, because the
    # first is malformed and the second is the one component that could
    # reach above the tree being extracted.
    raw = [part for part in trimmed.split("/") if part != "."]
    if not raw or any(part in ("", "..") for part in raw):
        raise RuntimeError(f"unsafe archive path rejected: {name!r}")
    return tuple(raw)


def _normalise_link_target(target: str, member_parts, *, hardlink=False):
    """Resolve a tar link target lexically in the guest root.

    Symlink targets may be absolute in guest notation, which means guest
    root, not Android host root. Hardlink targets are archive-root-relative
    and are never allowed to be absolute.
    """
    if not isinstance(target, str) or not target or "\x00" in target:
        raise RuntimeError("malformed link target")
    if hardlink and target.startswith("/"):
        raise RuntimeError(f"absolute hardlink target rejected: {target!r}")
    if hardlink:
        base = []
    elif target.startswith("/"):
        base = []
    else:
        base = list(member_parts[:-1])
    result = list(base)
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not result:
                raise RuntimeError(f"escaping link target rejected: {target!r}")
            result.pop()
        else:
            result.append(part)
    if not result:
        raise RuntimeError("link target resolves to the guest root")
    return tuple(result)


def _resolve_guest_path(parts, symlinks, *, follow_final=True):
    """Resolve archive paths against the guest root, before any write.

    The walk is the kernel's, with the guest root standing in for ``/``,
    which is also how proot will present the tree at runtime:

      * a component naming an archive symlink is replaced by its target;
      * an absolute target restarts at the guest root, so a legitimate
        ``/bin -> /usr/bin`` resolves inside the guest rather than to the
        Android host's ``/usr/bin``;
      * ``..`` pops and is **clamped** at the root, so it can never ascend
        above the tree being written.

    Clamping rather than rejecting is deliberate. ``..`` cannot appear in a
    member *name* at all -- ``_normalise_member_name`` refuses those -- so
    the only source of one here is a symlink target, where it is ordinary:
    ``foo -> ../usr/lib`` is a perfectly normal relative link. The target
    was already checked by ``_normalise_link_target``, which rejects any
    that would escape when resolved from its own directory, so clamping
    keeps the whole walk inside the root without rejecting valid links.

    What this returns is where an entry *belongs*. Every write is still
    performed as a plain path under the staging root, and the archive's
    paths and links are validated first, so the answer cannot point out of
    it. A cycle is walked at most ``_MAX_SYMLINK_HOPS`` times (the kernel's
    own ELOOP limit) and is then rejected as malformed.
    """
    resolved = []
    pending = list(parts)
    hops = 0
    while pending:
        component = pending.pop(0)
        if component in ("", "."):
            continue
        if component == "..":
            if resolved:
                resolved.pop()
            continue
        candidate = tuple(resolved + [component])
        target = symlinks.get(candidate)
        if target is not None and (pending or follow_final):
            hops += 1
            if hops > _MAX_SYMLINK_HOPS:
                raise RuntimeError("cyclic or pathological symlink graph")
            if target.startswith("/"):
                resolved = []
            pending = target.split("/") + pending
        else:
            resolved.append(component)
    return tuple(resolved)


def _terminal_regular(record, by_path, symlinks):
    """Return the regular archive member a hardlink chain ends at.

    ``a -> b``, ``b -> c``, ``c`` regular is a perfectly ordinary shape --
    Debian ships it (``usr/bin/uncompress -> bin/gunzip`` where ``bin`` is
    itself a symlink) -- and resolving it from the archive rather than from
    what happens to be on disk is what lets the links be created in any
    order at all.

    A chain that revisits a name is a cycle, and one that ends anywhere but
    at a regular member (a directory, a symlink, a device, or nothing in the
    archive) has no bytes to copy. Both are malformed input rather than a
    reason to produce a rootfs that is quietly wrong, so both are rejected
    here, before activation, instead of at link time.
    """
    seen = set()
    current_parts = record["parts"]
    while True:
        if current_parts in seen:
            raise RuntimeError(
                f"cyclic hardlink graph rejected: {record['member'].name!r}"
            )
        seen.add(current_parts)
        node = by_path.get(current_parts)
        if node is None:
            raise RuntimeError(
                f"dangling hardlink target rejected: {record['member'].name!r}"
            )
        if node["kind"] == "regular":
            return node
        if node["kind"] != "hardlink":
            raise RuntimeError(
                f"hardlink target is not a regular archive file: "
                f"{record['member'].name!r}"
            )
        # Only the components *above* the final one are followed: a
        # hardlink may name a path that sits behind a symlinked directory
        # (``uncompress -> bin/gunzip``, where ``bin`` is ``usr/bin``), but
        # a chain that *ends* at a symlink has no regular file to copy and
        # is rejected rather than guessed at.
        current_parts = _resolve_guest_path(
            _normalise_link_target(node["target"], node["parts"],
                                   hardlink=True),
            symlinks,
            follow_final=False,
        )


def _probe_hardlinks(root: Path):
    """Probe the staging filesystem rather than assuming an Android policy.

    The probe runs inside the rootfs being written, which is on the same
    filesystem the finished Buster tree will live on -- archive paths,
    modes and hardlinks all behave differently across a mount boundary,
    so testing anywhere else answers a different question.

    Three distinct answers are folded into ``False`` because they mean the
    same thing to the caller -- materialize the link instead:

      * the interpreter has no ``os.link`` at all (Termux/Android CPython,
        where the attribute is simply absent);
      * the call exists and the filesystem refuses it (EPERM on Android
        app-private data, EROFS, ENOTSUP);
      * the call exists but this device cannot make another link (EXDEV,
        EMLINK).

    An unexpected errno is deliberately *not* swallowed: it would mean the
    probe learned nothing about the filesystem, and continuing would let a
    permission or quota problem decide the extraction strategy silently.
    """
    if _link_fn is None:
        return False
    probe_dir = root / ".hardlink-probe"
    probe_dir.mkdir(mode=0o700, exist_ok=True)
    source, target = probe_dir / "source", probe_dir / "target"
    try:
        source.write_bytes(b"probe")
        _link_fn(source, target)
        return True
    except OSError as exc:
        if exc.errno in _LINK_UNSUPPORTED_ERRNOS:
            return False
        raise
    finally:
        if probe_dir.exists():
            shutil.rmtree(probe_dir, ignore_errors=True)


def _hash_file(path: Path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_members(archive: Path):
    """Preflight the complete archive before allowing archive data to write."""
    members = []
    by_path = {}
    symlinks = {}
    hardlinks = 0
    total_size = 0
    with tarfile.open(archive, "r:*") as tf:
        for count, member in enumerate(tf, 1):
            if count > _MAX_MEMBERS:
                raise RuntimeError("archive contains too many members")
            try:
                parts = _normalise_member_name(member.name)
            except RuntimeError:
                # A tar made from the filesystem root commonly contains a
                # harmless ``./`` directory entry. It denotes the guest
                # root, not a host path, and is accepted only as a directory.
                if member.isdir() and member.name.rstrip("/") in ("", "."):
                    parts = ()
                else:
                    raise
            if parts in by_path:
                raise RuntimeError(f"duplicate archive member rejected: {member.name!r}")
            if member.isreg():
                total_size += max(member.size, 0)
                if total_size > _MAX_ARCHIVE_BYTES:
                    raise RuntimeError("archive contains too much regular-file data")
                kind = "regular"
                target = None
            elif member.isdir():
                kind = "directory"
                target = None
            elif member.issym():
                # Store the raw target so extraction preserves the canonical
                # link exactly; validate its guest-root interpretation now.
                _normalise_link_target(member.linkname, parts)
                kind = "symlink"
                target = member.linkname
                symlinks[parts] = member.linkname
            elif member.islnk():
                hardlinks += 1
                if hardlinks > _MAX_LINKS:
                    raise RuntimeError("archive contains too many hardlinks")
                _normalise_link_target(member.linkname, parts, hardlink=True)
                kind = "hardlink"
                target = member.linkname
            else:
                # Devices, FIFOs, sockets, GNU sparse pseudo entries and
                # unknown types are never created from an untrusted archive.
                raise RuntimeError(f"unsupported archive member type: {member.name!r}")
            record = {"member": member, "parts": parts, "kind": kind,
                      "target": target}
            members.append(record)
            by_path[parts] = record

    # Resolve every symlink node too, even when no later member references
    # it. A cyclic link graph is malformed release input, not a reason to
    # defer failure until a shell happens to traverse it.
    for record in members:
        if record["kind"] == "symlink":
            _resolve_guest_path(record["parts"], symlinks,
                                follow_final=True)

    # Resolve all destination parents and link sources using only the
    # preflight graph. This prevents a later archive symlink from turning a
    # normal host path operation into an extraction escape.
    effective = {}
    for record in members:
        parts = record["parts"]
        # Never follow the final member name. A symlink entry must be
        # created at its own name; only its parent components are resolved.
        effective[parts] = _resolve_guest_path(parts, symlinks,
                                               follow_final=False)
        if record["kind"] == "hardlink":
            link_parts = _normalise_link_target(record["target"], parts,
                                                 hardlink=True)
            record["source_parts"] = _resolve_guest_path(link_parts, symlinks,
                                                         follow_final=False)
            # Follow the chain to the regular member the bytes really come
            # from. Resolving it here, from the archive alone, is what makes
            # the extraction independent of member order: whether the link
            # is listed before or after its target changes nothing.
            record["source_record"] = _terminal_regular(record, by_path,
                                                        symlinks)
        record["effective_parts"] = effective[parts]

    # Two archive names resolving to one write path are ambiguous and could
    # otherwise make extraction order part of the security model.
    destinations = {}
    for record in members:
        if record["kind"] == "hardlink":
            continue
        destination = record["effective_parts"]
        previous = destinations.get(destination)
        if previous is not None:
            raise RuntimeError("archive entries resolve to the same destination")
        destinations[destination] = record
    return members, by_path


def _set_times(path, mtime):
    """Apply an archive timestamp best-effort.

    Timestamps are fidelity, not correctness: a filesystem or interpreter
    that cannot set one still gets a rootfs whose bytes and modes are
    right, so a refusal here must never fail an installation. The errnos a
    real filesystem returns for this are wrapped alongside the
    NotImplementedError an interpreter without the call raises, which is
    the same shape as the missing os.link the capability probe handles.
    """
    try:
        os.utime(path, (mtime, mtime), follow_symlinks=False)
    except (OSError, NotImplementedError, ValueError):
        pass


def _copy_bytes(source: Path, destination: Path, source_record):
    """Materialize one hardlink as an independent file.

    The bytes and the metadata are both the *target's*, because that is
    what a hardlink is: a second name for one inode, not a file with a
    metadata block of its own. Copying the target's mode and timestamp as
    well as its contents is what makes the result indistinguishable from
    the canonical rootfs under a filesystem that cannot share the inode.
    """
    member = source_record["member"]
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with source.open("rb") as src, destination.open("wb") as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)
    os.chmod(destination, stat.S_IMODE(member.mode))
    _set_times(destination, member.mtime)


def _extract(archive: Path, root: Path):
    """Extract a validated rootfs, preserving modes and handling hardlinks."""
    members, _by_path = _read_members(archive)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    native_links = _probe_hardlinks(root)
    directories = []
    symlinks = {record["parts"]: record["target"] for record in members
                if record["kind"] == "symlink"}

    with tarfile.open(archive, "r:*") as tf:
        # TarInfo objects retain their member names; find the corresponding
        # record by normalized name and extract only regular data members.
        records_by_name = {record["member"].name: record for record in members}
        for member in tf:
            record = records_by_name[member.name]
            if not record["parts"]:
                continue
            destination = root.joinpath(*record["effective_parts"])
            kind = record["kind"]
            if kind == "directory":
                destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                directories.append((destination, member.mode, member.mtime))
            elif kind == "symlink":
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.symlink(member.linkname, destination)
                _set_times(destination, member.mtime)
            elif kind == "regular":
                source = tf.extractfile(member)
                if source is None:
                    raise RuntimeError(f"cannot read archive member {member.name!r}")
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with destination.open("wb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                os.chmod(destination, stat.S_IMODE(member.mode))
                _set_times(destination, member.mtime)

    # Even a filesystem that allows link(2) is no use if the interpreter
    # cannot call it, so the capability is gated once here rather than
    # being discovered one failed member at a time.
    native_links = native_links and _link_fn is not None

    # Every remaining member is a hardlink whose chain was already resolved
    # to a regular file during preflight, and every regular file is already
    # on disk. There is therefore nothing left to order and nothing left to
    # discover: each link is made (or materialized) against a target that is
    # known to exist and known to be regular.
    pending = [record for record in members if record["kind"] == "hardlink"]
    for record in pending:
        source_record = record["source_record"]
        source = root.joinpath(*source_record["effective_parts"])
        destination = root.joinpath(*record["effective_parts"])
        if not source.is_file() or source.is_symlink():
            raise RuntimeError(
                f"hardlink target is not a regular file on disk: "
                f"{source_record['member'].name!r}"
            )
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if native_links:
            try:
                _link_fn(source, destination)
            except OSError as exc:
                # The probe said this filesystem honours link(2); one
                # member failing anyway means it does not, and the rest of
                # the graph is materialized from here on. Anything that is
                # not an unsupported-filesystem errno is a real failure of
                # this extraction, not a capability answer.
                if exc.errno not in _LINK_UNSUPPORTED_ERRNOS:
                    raise
                native_links = False
                _copy_bytes(source, destination, source_record)
        else:
            _copy_bytes(source, destination, source_record)

        # A hardlink is one inode under two names, so it has exactly one set
        # of metadata and it is the target's. The canonical Buster v0.3.2
        # tarball records 0777 on its LNK headers while the linked file's own
        # header carries the real mode (0755 for usr/bin/perl), so honouring
        # the link header would hand every Debian hardlink an executable,
        # world-writable mode that the Linux rootfs never had. In the native
        # case the inode already holds the target's metadata, so nothing is
        # written at all -- changing it through the alias would change the
        # target too. In the materialized case the copy inherits it.

    for directory, mode, mtime in reversed(directories):
        os.chmod(directory, stat.S_IMODE(mode))
        _set_times(directory, mtime)
    return native_links


def _state():
    try:
        state_dir_fd = statedir.open_state_dir(BUSTER_DIR)
        try:
            state_fd, _st = dirfd.open_regular_at(state_dir_fd, "state.json",
                                                   os.O_RDONLY)
        finally:
            os.close(state_dir_fd)
        with os.fdopen(state_fd, encoding="utf-8") as stream:
            data = json.load(stream)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def _validate_version(version: str):
    if (not isinstance(version, str) or not version or version in (".", "..")
            or "/" in version or "\\" in version or "\x00" in version):
        raise RuntimeError("invalid Buster release version")


def _prepare_rootfs(root: Path, arch: str):
    """Validate the staged release, then give it the config it cannot ship.

    Debian does not ship ``/etc/resolv.conf``: there is normally a boot
    sequence that writes it from whatever network configuration the kernel
    was handed. Buster under proot has no such boot, and Android has no
    resolver file of its own to borrow, so the file is written explicitly
    here. This is the same helper every other proot-distro image install
    goes through, applied to TerminalP's own guest, and it is part of the
    replaceable rootfs rather than persistent state: a new release gets a
    freshly generated one rather than inheriting an old release's.
    """
    _validate_rootfs(root, arch)
    rootfs_helpers.write_resolv_conf(str(root))


def _validate_rootfs(root: Path, arch: str, root_fd=None):
    """Validate active rootfs structure and explicit device architecture."""
    if _ARCH_MAP.get(get_device_cpu_arch()) != arch:
        raise RuntimeError(
            f"Buster architecture {arch!r} does not match device "
            f"{get_device_cpu_arch()!r}"
        )
    required = ("usr", "etc", "var", "tmp", "run", "dev", "proc",
                "sys", "home", "root")
    if root_fd is None:
        entries = [
            (name, root / name)
            for name in required + ("bin", "sbin", "lib")
        ]
        missing = [name for name, path in entries[:len(required)]
                   if not os.path.lexists(path)]
    else:
        names = required + ("bin", "sbin", "lib")
        missing = [name for name in names[:len(required)]
                   if not _entry_exists(root_fd, name)]
        entries = [(name, name) for name in names]
    if missing:
        raise RuntimeError("Buster rootfs missing required paths: " + ", ".join(missing))
    for name, path in entries[len(required):]:
        if root_fd is None:
            if not os.path.lexists(path):
                continue
            mode = os.lstat(path).st_mode
        else:
            if not _entry_exists(root_fd, name):
                continue
            mode = os.stat(name, dir_fd=root_fd, follow_symlinks=False).st_mode
        if not stat.S_ISLNK(mode):
            continue
        target = (os.readlink(path) if root_fd is None
                  else os.readlink(name, dir_fd=root_fd))
        _normalise_link_target(target, (name,))


def _entry_exists(root_fd, name):
    try:
        os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        return True
    except OSError:
        return False


def _load_release_metadata(path: str, version: str, arch: str):
    _validate_version(version)
    if not path:
        return {}
    with open(os.path.expanduser(path), encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise RuntimeError("Buster release metadata must be a JSON object")
    metadata_version = data.get("version")
    metadata_arch = data.get("architecture", data.get("arch"))
    if metadata_version not in (None, version) or metadata_arch not in (None, arch):
        raise RuntimeError("Buster release metadata version/architecture mismatch")
    digest = data.get("sha256") or data.get("digest")
    if isinstance(digest, str) and digest.startswith("sha256:"):
        digest = digest[7:]
    if digest and (not isinstance(digest, str) or len(digest) != 64):
        raise RuntimeError("Buster release metadata contains an invalid SHA-256")
    return {"sha256": digest.lower()} if digest else {}


def _ensure_persistent():
    _ensure_state_dirs()
    paths = (
        Path(PERSISTENT_DIR) / "root",
        Path(PERSISTENT_DIR) / "home",
        Path(PERSISTENT_DIR) / "runtime" / "tmp",
        Path(PERSISTENT_DIR) / "runtime" / "run",
    )
    for path in paths:
        fd = statedir.open_state_dir(str(path), create=True)
        os.close(fd)
    os.chmod(paths[2], 0o1777)
    os.chmod(paths[3], 0o755)
    return paths[0], paths[1], paths[2], paths[3]


def _terminalp_version():
    """The TerminalP build this guest is being hosted by.

    Read from the app's own environment, which the TerminalP shell already
    exports, so the marker says which build is hosting Buster rather than
    being a constant that silently goes stale.
    """
    return (os.environ.get("TERMUX_APP__APP_VERSION_NAME")
            or os.environ.get("TERMINALP_VERSION")
            or "primetech")


def _launcher_environment():
    """Construct the guest launcher environment from an explicit allowlist.

    Buster identifies its host one of two ways: from a ``PREFIX`` path, or
    from a ``TERMINALP_VERSION`` marker. Only the marker is exported.
    ``PREFIX`` is deliberately *not* -- it is a path variable that guest
    tooling would use to resolve its own binaries and libraries, which is
    exactly the override this environment exists to prevent. The marker
    carries identity and nothing else, so Buster's ``doctor`` detects
    TerminalP correctly while Buster's userspace stays its own.
    """
    return {
        "HOME": "/root",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TERM": os.environ.get("TERM", "xterm-256color"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERMINALP_VERSION": _terminalp_version(),
    }


def _active_root(state):
    version = state.get("version")
    _validate_version(version)
    return Path(RELEASES_DIR) / version / "rootfs"


def _pin_active_root(state):
    version = state.get("version")
    _validate_version(version)
    releases_fd = statedir.open_state_dir(RELEASES_DIR)
    try:
        root_fd = dirfd.descend_at(releases_fd, (version, "rootfs"))
    except BaseException:
        os.close(releases_fd)
        raise
    os.close(releases_fd)
    try:
        _validate_rootfs(_active_root(state), state["architecture"], root_fd)
    except BaseException:
        os.close(root_fd)
        raise
    return root_fd


def _is_owned_directory(path: Path):
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


def _remove_incomplete(staging: Path, release: Path, version: str):
    """Clean up an installation that did not reach a published state.

    Activation happens only when the state record is written, so a release
    directory that the state record does not point at is a deployment that
    was interrupted part-way -- however it was interrupted -- and is
    removed rather than being left behind looking installed.
    """
    if staging.exists():
        _remove_state_tree(str(staging))
    if _is_owned_directory(release) and _state().get("version") != version:
        _remove_state_tree(str(release))


def _install(args):
    try:
        _validate_version(args.version)
    except RuntimeError as exc:
        crit_error(str(exc))
        sys.exit(1)
    if not args.archive or not args.version or not args.architecture:
        crit_error("buster install requires ARCHIVE, --version and --architecture")
        sys.exit(1)
    if args.architecture not in set(_ARCH_MAP.values()):
        crit_error(f"unsupported Buster architecture: {args.architecture}")
        sys.exit(1)

    # Architecture is checked against the device before the artifact is
    # unpacked, not after. A mapping that does not exist fails closed rather
    # than falling back to another artifact, and a mismatched artifact is
    # refused without first spending minutes extracting it onto the phone.
    device_arch = get_device_cpu_arch()
    expected_arch = _ARCH_MAP.get(device_arch)
    if expected_arch is None:
        crit_error(f"unknown device architecture: {device_arch}")
        sys.exit(1)
    if args.architecture != expected_arch:
        crit_error(
            f"Buster architecture mismatch: device {device_arch} requires "
            f"{expected_arch}, not {args.architecture}"
        )
        sys.exit(1)
    archive = Path(os.path.expanduser(args.archive)).resolve()
    if not archive.is_file():
        crit_error(f"Buster archive does not exist: {archive}")
        sys.exit(1)
    metadata = _load_release_metadata(args.release_metadata, args.version,
                                      args.architecture)
    expected = (metadata.get("sha256") or args.sha256 or "").lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        crit_error("a published SHA-256 digest is required (--sha256 or --release-metadata)")
        sys.exit(1)
    actual = _hash_file(archive)
    if actual != expected:
        crit_error(f"Buster archive digest mismatch: expected {expected}, got {actual}")
        sys.exit(1)

    _ensure_state_dirs()
    release = Path(RELEASES_DIR) / args.version
    staging = Path(RELEASES_DIR) / f".{args.version}.staging-{os.getpid()}"
    with ContainerLock("buster", exclusive=True, command="buster-install"):
        current = _state()
        if os.path.lexists(release) and not _is_owned_directory(release):
            crit_error(f"Buster release path is not a private directory: {release}")
            sys.exit(1)
        if _is_owned_directory(release):
            if (current.get("version") == args.version
                    and current.get("sha256") == actual):
                # Already installed from this exact artifact: rerunning is a
                # no-op, but the on-disk tree is still checked rather than
                # being trusted because the state record says so.
                _validate_rootfs(release / "rootfs", args.architecture)
                msg(f"{C['CYAN']}Buster {args.version} is already active{C['RST']}")
                return
            if current.get("version") == args.version:
                crit_error(
                    f"Buster {args.version} is active from a different artifact "
                    f"({current.get('sha256')}); refusing to replace it"
                )
                sys.exit(1)
            # No state record points at this release, so it is the residue of
            # an interrupted deployment and is safe to rebuild.
            msg(f"removing interrupted Buster {args.version} deployment")
            _remove_state_tree(str(release))
        if staging.exists():
            _remove_state_tree(str(staging))
        staging.mkdir(mode=0o700, parents=True)
        try:
            native = _extract(archive, staging / "rootfs")
            _prepare_rootfs(staging / "rootfs", args.architecture)
            # Activation is one rename: nothing below has been touched in
            # place, and the release directory appears complete or not at
            # all. Persistent state is deliberately *not* staged here -- it
            # lives outside releases/ so an upgrade cannot treat user state
            # as part of the rootfs being replaced.
            os.replace(staging, release)
            _ensure_persistent()
            new_state = {
                "version": args.version,
                "architecture": args.architecture,
                "artifact": archive.name,
                "sha256": actual,
                "state": "active",
                "native_hardlinks": native,
            }
            with atomic_write(STATE_FILE, "w", encoding="utf-8") as stream:
                json.dump(new_state, stream, indent=2, sort_keys=True)
        except (RuntimeError, OSError) as exc:
            # A malformed, unsafe or unreadable archive is a failed install,
            # not a crash: the previous working release is left untouched and
            # the reason is reported.
            _remove_incomplete(staging, release, args.version)
            crit_error(f"Buster installation failed: {exc}")
            sys.exit(1)
        except Exception:
            _remove_incomplete(staging, release, args.version)
            raise
    msg(f"{C['CYAN']}Buster {args.version} activated{C['RST']}")


def _verify():
    state = _state()
    try:
        root = _active_root(state)
        _validate_rootfs(root, state["architecture"])
        digest = state.get("sha256")
        msg(f"Buster {state['version']}: valid ({state['architecture']}, {digest})")
    except (KeyError, RuntimeError, OSError) as exc:
        crit_error(f"Buster verification failed: {exc}")
        sys.exit(1)


def _launcher_bindings(runtime_tmp, runtime_run, persistent_root,
                      persistent_home):
    """The complete, explicit set of host paths Buster is given.

    An allowlist rather than a subtraction. TerminalP's ``$PREFIX``,
    ``$HOME``, ``/data``, the app's private directories, shared storage and
    any root or Magisk interface are never added here, so there is nothing
    to remove and no variable that can re-introduce them at runtime.

    ``/dev``, ``/proc`` and ``/sys`` are the kernel views proot itself
    provides. ``/tmp`` and ``/run`` are Buster-private directories under the
    persistent tree, so the guest gets writable runtime locations without
    touching TerminalP's own. Everything else the guest sees is its own
    rootfs.
    """
    # /etc/resolv.conf is deliberately *not* bound in. Android has no
    # resolver file to lend -- /etc/resolv.conf does not exist on the
    # device -- and borrowing a host one when it does exist would make the
    # guest's resolver depend on which machine TerminalP happens to be
    # running on. The installed rootfs carries its own instead.
    return [
        "/dev",
        "/proc",
        "/sys",
        f"{runtime_tmp}:/tmp",
        f"{runtime_run}:/run",
        f"{persistent_root}:/root",
        f"{persistent_home}:/home",
    ]


def _launcher_argv(bindings):
    return [
        "--link2symlink", "--kill-on-exit", "--sysvipc",
        "-0", "--rootfs=.",
        *(f"--bind={binding}" for binding in bindings),
        "--cwd=/root",
    ]


def _pinned_executable(root_fd, parts):
    try:
        directory_fd = dirfd.descend_at(root_fd, parts[:-1])
    except OSError:
        return False
    try:
        executable_fd, executable_st = dirfd.open_regular_at(
            directory_fd, parts[-1], os.O_RDONLY
        )
    except OSError:
        os.close(directory_fd)
        return False
    os.close(executable_fd)
    os.close(directory_fd)
    return bool(executable_st.st_mode & 0o111)


def _launch_guest(inner, guest_parts):
    with ContainerLock("buster", exclusive=False, command="buster-exec",
                       inheritable=True):
        _launch_guest_locked(inner, guest_parts)


def _launch_guest_locked(inner, guest_parts):
    state = _state()
    root_fd = None
    try:
        root_fd = _pin_active_root(state)
        if not _pinned_executable(root_fd, guest_parts):
            guest_path = "/" + "/".join(guest_parts)
            raise RuntimeError(
                f"Buster rootfs does not contain an executable {guest_path}"
            )
        persistent_root, persistent_home, runtime_tmp, runtime_run = (
            _ensure_persistent()
        )
        proot = Path(TERMUX_PREFIX) / "bin" / "proot"
        if not proot.is_file() or not os.access(proot, os.X_OK):
            raise RuntimeError(
                f"TerminalP proot is not installed at {proot}; run pkg install proot"
            )
        bindings = _launcher_bindings(runtime_tmp, runtime_run,
                                      persistent_root, persistent_home)
        argv = [str(proot), *_launcher_argv(bindings), *inner]
        previous_fd = os.open(os.curdir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fchdir(root_fd)
            os.execvpe(proot, argv, _launcher_environment())
        except BaseException:
            os.fchdir(previous_fd)
            raise
        finally:
            os.close(previous_fd)
    except (KeyError, RuntimeError, OSError) as exc:
        crit_error(f"Buster launch refused: {exc}")
        sys.exit(1)
    finally:
        if root_fd is not None:
            os.close(root_fd)


def _exec_inner(tokens):
    tokens = list(tokens)
    if len(tokens) == 1 and tokens[0] in _EXEC_OPERATIONS:
        return ["/usr/bin/buster", "exec", tokens[0]]
    if (len(tokens) == 2 and tokens[0] in _SERVICE_OPERATIONS
            and _SERVICE_NAME.fullmatch(tokens[1])):
        return ["/usr/bin/buster", "exec", tokens[0], tokens[1]]
    crit_error(
        "buster exec supports only: status, services, capabilities, health, "
        "ping, service-start <name>, service-restart <name>, service-status <name>"
    )
    sys.exit(1)


def _exec(args):
    if any(getattr(args, name, None) for name in (
            "version", "architecture", "sha256", "release_metadata")):
        crit_error("buster exec does not accept deployment options")
        sys.exit(1)
    tokens = [args.archive, *(getattr(args, "exec_args", None) or [])]
    if tokens[0] is None:
        crit_error("buster exec requires a supported operation")
        sys.exit(1)
    _launch_guest(_exec_inner(tokens), ("usr", "bin", "buster"))


def _login():
    _launch_guest(["/bin/bash", "-l"], ("usr", "bin", "bash"))


def command_buster(args):
    """Dispatch the TerminalP Buster deployment command."""
    action = args.buster_action
    if action in ("install", "verify") and getattr(args, "exec_args", None):
        crit_error(f"unknown buster action argument: {args.exec_args[0]}")
        sys.exit(1)
    if action == "install":
        _install(args)
    elif action == "verify":
        _verify()
    elif action == "login":
        if args.archive is not None or getattr(args, "exec_args", None):
            crit_error("buster login does not accept positional arguments")
            sys.exit(1)
        _login()
    elif action == "exec":
        _exec(args)
    else:
        crit_error(f"unknown buster action: {action}")
        sys.exit(1)
