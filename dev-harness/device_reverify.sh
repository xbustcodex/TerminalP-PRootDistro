#!/bin/sh
# Re-verify the republished proot-distro on the real device: reinstall the
# package from the PrimeTech repository, then redeploy and launch Buster
# through the shipped CLI.

PREFIX=/data/data/com.primetech.terminal/files/usr
HOME_DIR=/data/data/com.primetech.terminal/files/home

export PREFIX
export HOME="$HOME_DIR"
export PATH="$PREFIX/bin:$PREFIX/bin/applets"
export LD_LIBRARY_PATH="$PREFIX/lib"
export TERMUX_APP__PACKAGE_NAME=com.primetech.terminal
export TERMUX__PREFIX="$PREFIX"
export TERMUX__HOME="$HOME_DIR"
export TERMUX_APP__APP_VERSION_NAME=0.118.3-primetech
export TMPDIR="$PREFIX/tmp"

echo "=== reinstall the republished package ==="
pkg uninstall -y proot-distro 2>&1 | tail -4
pkg install -y proot-distro 2>&1 | tail -6

echo
echo "=== the shipped module matches the corrected source ==="
grep -c "staging / \"persistent\"" "$PREFIX/lib/python3.14/site-packages/proot_distro/commands/buster.py" || true
grep -n "Activation is one rename" "$PREFIX/lib/python3.14/site-packages/proot_distro/commands/buster.py"

echo
echo "=== fresh deployment, with a previous release already present ==="
mkdir -p "$PREFIX/var/lib/proot-distro/buster/releases/0.3.1/rootfs"
for d in usr etc var tmp run dev proc sys home root; do
  mkdir -p "$PREFIX/var/lib/proot-distro/buster/releases/0.3.1/rootfs/$d"
done
echo "previous release sentinel" > "$PREFIX/var/lib/proot-distro/buster/releases/0.3.1/rootfs/usr/sentinel"
rm -rf "$PREFIX/var/lib/proot-distro/buster/releases/0.3.2"

proot-distro buster install "$HOME_DIR/buster-os-0.3.2-arm64-bookworm.tar.gz" \
  --version 0.3.2 --architecture arm64 \
  --sha256 86dc6cf110c9db10da94d13e1098850cb4bfd09e3b16d0478bfb7fd0fa15af87 2>&1 | tail -4

echo "--- previous release survived ---"
ls -la "$PREFIX/var/lib/proot-distro/buster/releases/0.3.1/rootfs/usr/sentinel" 2>&1
echo "--- the dead per-release persistent/ directory is gone ---"
ls -la "$PREFIX/var/lib/proot-distro/buster/releases/0.3.2/" 2>&1

echo
echo "=== verify ==="
proot-distro buster verify 2>&1 | tail -3

echo
echo "=== idempotent rerun ==="
proot-distro buster install "$HOME_DIR/buster-os-0.3.2-arm64-bookworm.tar.gz" \
  --version 0.3.2 --architecture arm64 \
  --sha256 86dc6cf110c9db10da94d13e1098850cb4bfd09e3b16d0478bfb7fd0fa15af87 2>&1 | tail -2

echo
echo "=== launch and smoke test through the shipped CLI ==="
{
  echo "whoami"
  echo "uname -m"
  echo "grep PRETTY_NAME /etc/os-release"
  echo "dpkg --print-architecture"
  echo "bash --version | head -1"
  echo "python3 --version"
  echo "git --version"
  echo "ls -ld /bin /sbin /lib"
  echo "ls -la /usr/bin/perl5.36.0 /usr/bin/perlthanks /usr/bin/perl /usr/bin/perlbug /usr/bin/uncompress"
  echo "perl5.36.0 -e 'print \"perl5.36.0 executes\\n\"'"
  echo "perlthanks --version 2>&1 | head -1"
  echo "uncompress --version | head -1"
  echo "for d in bin usr etc var home root tmp run proc sys dev; do [ -e /\$d ] && echo \"/\$d present\" || echo \"/\$d MISSING\"; done"
  echo "touch /tmp/.t && echo '/tmp writable' && rm -f /tmp/.t"
  echo "touch /run/.t && echo '/run writable' && rm -f /run/.t"
  echo "python3 -c \"import socket;print('dns', socket.gethostbyname('deb.debian.org'))\""
  echo "python3 -c \"import urllib.request;print('http', urllib.request.urlopen('http://deb.debian.org', timeout=20).status)\""
  echo "echo TERMINALP_VERSION=\$TERMINALP_VERSION PREFIX=[\$PREFIX]"
  echo "python3 -c \"from buster.android_integration import device;print('host', device.host_identity())\""
  echo "python3 -m buster.cli version"
  echo "exit"
} | proot-distro buster login 2>&1 | tail -32

echo
echo "=== package already current (update path is idempotent) ==="
pkg install -y proot-distro 2>&1 | tail -3
proot-distro buster verify 2>&1 | tail -2
