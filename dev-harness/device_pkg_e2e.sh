#!/bin/sh
# Real end-to-end acceptance on the TerminalP device: install the published
# package through the PrimeTech repository, then deploy and launch Buster
# using the shipped CLI only.

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

echo "=== repository configuration on the device ==="
# Print whatever repositories are actually configured rather than assuming a
# particular builder host. This keeps the harness free of fixed local
# infrastructure addresses.
grep -rhsE "^(deb|Types:|URIs:|Suites:|Components:)" \
  "$PREFIX/etc/apt/sources.list" "$PREFIX/etc/apt/sources.list.d/" 2>/dev/null | head -10

echo
echo "=== pkg update ==="
pkg update 2>&1 | tail -8

echo
echo "=== pkg install proot-distro ==="
pkg install -y proot-distro 2>&1 | tail -15

echo
echo "=== the installed command ==="
command -v proot-distro
proot-distro --version 2>&1 | head -3

echo
echo "=== the buster subcommand is available in the shipped CLI ==="
proot-distro buster --help 2>&1 | head -20

echo
echo "=== fresh Buster install through the shipped CLI ==="
rm -rf "$PREFIX/var/lib/proot-distro/buster"
proot-distro buster install "$HOME_DIR/buster-os-0.3.2-arm64-bookworm.tar.gz" \
  --version 0.3.2 --architecture arm64 \
  --sha256 86dc6cf110c9db10da94d13e1098850cb4bfd09e3b16d0478bfb7fd0fa15af87 2>&1 | tail -10

echo
echo "=== install again (idempotence) ==="
proot-distro buster install "$HOME_DIR/buster-os-0.3.2-arm64-bookworm.tar.gz" \
  --version 0.3.2 --architecture arm64 \
  --sha256 86dc6cf110c9db10da94d13e1098850cb4bfd09e3b16d0478bfb7fd0fa15af87 2>&1 | tail -5

echo
echo "=== wrong architecture must be refused ==="
proot-distro buster install "$HOME_DIR/buster-os-0.3.2-arm64-bookworm.tar.gz" \
  --version 0.3.3 --architecture amd64 \
  --sha256 86dc6cf110c9db10da94d13e1098850cb4bfd09e3b16d0478bfb7fd0fa15af87 2>&1 | tail -4

echo
echo "=== digest mismatch must be refused ==="
proot-distro buster install "$HOME_DIR/buster-os-0.3.2-arm64-bookworm.tar.gz" \
  --version 0.3.4 --architecture arm64 --sha256 0000000000000000000000000000000000000000000000000000000000000000 2>&1 | tail -4

echo
echo "=== verify ==="
proot-distro buster verify 2>&1 | tail -5

echo
echo "=== install record on disk ==="
cat "$PREFIX/var/lib/proot-distro/buster/state.json"

echo
echo "=== launch through the shipped CLI and run the guest smoke test ==="
{
  echo "whoami"
  echo "uname -m"
  echo "grep PRETTY_NAME /etc/os-release"
  echo "dpkg --print-architecture"
  echo "bash --version | head -1"
  echo "python3 --version"
  echo "git --version"
  echo "ls -ld /bin /sbin /lib"
  echo "ls -la /usr/bin/perl5.36.0 /usr/bin/perl /usr/bin/uncompress"
  echo "perl5.36.0 -e 'print \"perl5.36.0 executes\\n\"'"
  echo "uncompress --version | head -1"
  echo "cat /etc/resolv.conf"
  echo "python3 -c \"import socket;print('dns', socket.gethostbyname('deb.debian.org'))\""
  echo "python3 -c \"import urllib.request;print('http', urllib.request.urlopen('http://deb.debian.org', timeout=20).status)\""
  echo "echo TERMINALP_VERSION=\$TERMINALP_VERSION PREFIX=\$PREFIX"
  echo "python3 -c \"from buster.android_integration import device; print('host', device.host_identity())\""
  echo "exit"
} | proot-distro buster login 2>&1 | tail -30

echo
echo "=== idempotence of the update path (package already current) ==="
pkg install -y proot-distro 2>&1 | tail -5
proot-distro buster verify 2>&1 | tail -3
