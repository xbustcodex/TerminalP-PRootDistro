"""Drive the real `buster install` -> `verify` -> launcher path on TerminalP.

This does not re-implement anything: it sets the environment TerminalP's own
shell provides, then calls the shipped command functions exactly as the CLI
does, so staging, activation, state recording and the launcher are all the
real code paths. The smoke test at the end runs through the launcher's own
argv and environment via subprocess instead of os.execvpe, so its output can
be captured.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

PREFIX = "/data/data/com.primetech.terminal/files/usr"
HOME = "/data/data/com.primetech.terminal/files/home"

# TerminalP's shell exports these; constants.py reads them at import time, so
# they must be set before proot_distro is imported.
os.environ.update({
    "TERMUX_APP__PACKAGE_NAME": "com.primetech.terminal",
    "TERMUX__PREFIX": PREFIX,
    "TERMUX__HOME": HOME,
    "TERMUX_APP__APP_VERSION_NAME": "0.118.3-primetech",
    "TERMUX_VERSION": "primetech",
})

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proot_distro.commands import buster  # noqa: E402
from proot_distro import constants  # noqa: E402

print("=== environment model ===")
print("TERMUX_PREFIX   = %s" % constants.TERMUX_PREFIX)
print("RUNTIME_DIR     = %s" % constants.RUNTIME_DIR)
print("IS_TERMUX       = %r" % constants.IS_TERMUX)
print("BUSTER_DIR      = %s" % buster.BUSTER_DIR)

archive = Path(sys.argv[1]).resolve()
sha256 = sys.argv[2]
version = sys.argv[3] if len(sys.argv) > 3 else "0.3.2"
architecture = sys.argv[4] if len(sys.argv) > 4 else "arm64"

# The staging area is deliberately the real one: same filesystem as the
# finished installation, which is what makes the hardlink probe meaningful.
if Path(buster.BUSTER_DIR).exists():
    shutil.rmtree(buster.BUSTER_DIR)

# A pre-existing "previous working release" so rollback can be observed
# rather than merely asserted.
previous = Path(buster.RELEASES_DIR) / "0.3.1" / "rootfs"
previous.mkdir(parents=True)
(previous / "usr").mkdir()
(previous / "etc").mkdir()
(previous / "var").mkdir()
for name in ("tmp", "run", "dev", "proc", "sys", "home", "root"):
    (previous / name).mkdir()
(previous / "usr" / "sentinel-release-0.3.1").write_text("previous release\n")
print("\nseeded a previous working release at %s" % previous)

args = argparse.Namespace(
    archive=str(archive),
    version=version,
    architecture=architecture,
    sha256=sha256,
    release_metadata=None,
)

print("\n=== install (real command path) ===")
started = time.time()
buster._install(args)
print("install completed in %.1fs" % (time.time() - started))

print("\n=== rollback evidence: previous release survived activation ===")
print("  0.3.1 sentinel still present = %s"
      % (previous / "usr" / "sentinel-release-0.3.1").is_file())
print("  active state              = %s" % buster._state())

print("\n=== idempotence: rerunning install on a correct installation ===")
buster._install(args)
print("  state unchanged           = %s" % buster._state())

print("\n=== verify (real command path, independent of the state record) ===")
buster._verify()

print("\n=== failed install must preserve the working release ===")
bad = argparse.Namespace(
    archive=str(archive), version="0.3.3", architecture=architecture,
    sha256="0" * 64, release_metadata=None,
)
try:
    buster._install(bad)
except SystemExit as exc:
    print("  digest mismatch rejected with exit code %s" % exc.code)
print("  active version after refusal = %s" % buster._state().get("version"))
print("  0.3.3 was never created        = %s"
      % (not (Path(buster.RELEASES_DIR) / "0.3.3").exists()))

wrong = argparse.Namespace(
    archive=str(archive), version="0.3.4", architecture="amd64",
    sha256=sha256, release_metadata=None,
)
try:
    buster._install(wrong)
except SystemExit as exc:
    print("  wrong architecture rejected with exit code %s" % exc.code)

root = buster._active_root(buster._state())
persistent_root, persistent_home, runtime_tmp, runtime_run = buster._ensure_persistent()
bindings = buster._launcher_bindings(runtime_tmp, runtime_run,
                                     persistent_root, persistent_home)
launcher_env = buster._launcher_environment()
proot = str(Path(constants.TERMUX_PREFIX) / "bin" / "proot")
argv = [proot, *buster._launcher_argv(root, bindings), "/bin/bash", "-l"]

print("\n=== the single supported launcher argv ===")
print("  " + " ".join(argv))
print("=== deliberately constructed guest environment ===")
print("  " + repr(launcher_env))

SMOKE = r"""
echo "--- identity ---"
whoami
echo "--- architecture ---"
uname -m
echo "--- os-release ---"
cat /etc/os-release
echo "--- dpkg architecture ---"
dpkg --print-architecture
echo "--- toolchain ---"
bash --version | head -1
python3 --version
git --version
echo "--- merged-/usr ---"
ls -ld /bin /sbin /lib
echo "--- tree ---"
for d in bin usr etc var home root tmp run proc sys dev; do
  if [ -e "/$d" ]; then echo "  /$d present"; else echo "  /$d MISSING"; fi
done
echo "--- writable runtime dirs ---"
touch /tmp/.smoke-tmp && echo "  /tmp writable" && rm -f /tmp/.smoke-tmp
touch /run/.smoke-run && echo "  /run writable" && rm -f /run/.smoke-run
echo "--- resolv.conf ---"
cat /etc/resolv.conf
echo "--- DNS resolution ---"
getent hosts deb.debian.org || python3 -c "import socket;print(socket.gethostbyname('deb.debian.org'))"
echo "--- outbound network ---"
python3 -c "import urllib.request;print('http', urllib.request.urlopen('http://deb.debian.org', timeout=20).status)"
echo "--- guest apt is Debian, not TerminalP ---"
cat /etc/apt/sources.list 2>/dev/null | grep -v '^#' | head -5
echo "--- apt sees arm64 ---"
dpkg --print-architecture
echo "--- representative ELF execution ---"
perl -e 'print "perl ok\n"'
/bin/echo "coreutils ok"
echo 'print("python ok")' | python3
echo "--- Buster runtime present ---"
ls /opt/buster 2>/dev/null || echo "  no /opt/buster"
echo "--- Buster host identity ---"
python3 -c "import sys;sys.path.insert(0,'/opt/buster/lib');import buster;print('buster module', getattr(buster,'__version__','(no __version__)'))" 2>&1 | head -3
"""

print("\n=== in-guest smoke test through the launcher ===")
completed = subprocess.run(
    [*argv, "-c", SMOKE],
    env=launcher_env,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    timeout=900,
)
sys.stdout.write(completed.stdout.decode("utf-8", "replace"))
print("launcher exit code = %d" % completed.returncode)
