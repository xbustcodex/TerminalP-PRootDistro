"""Run a shell script inside the installed Buster guest using the real launcher.

The launcher argv and environment come from the shipped `buster` command
itself, so what runs here is the same command `proot-distro buster login`
would exec -- only via subprocess, so its output can be captured instead of
replacing this process.
"""

import os
import subprocess
import sys
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
from proot_distro import constants  # noqa: E402

script = Path(sys.argv[1]).read_text()

state = buster._state()
root = buster._active_root(state)
persistent_root, persistent_home, runtime_tmp, runtime_run = buster._ensure_persistent()
bindings = buster._launcher_bindings(runtime_tmp, runtime_run,
                                     persistent_root, persistent_home)
argv = [str(Path(constants.TERMUX_PREFIX) / "bin" / "proot"),
        *buster._launcher_argv(bindings), "/bin/bash", "-l"]

print("rootfs  = %s" % root)
print("active  = %s" % state)
print("argv    = %s" % " ".join(argv))
print("-" * 72)

completed = subprocess.run(
    [*argv, "-c", script],
    env=buster._launcher_environment(),
    cwd=root,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    timeout=900,
)
sys.stdout.write(completed.stdout.decode("utf-8", "replace"))
print("-" * 72)
print("launcher exit code = %d" % completed.returncode)
