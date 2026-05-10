#!/bin/sh

set -eu

usage() {
	cat <<'EOF'
usage: contrib/build-rust-crypto-macos.sh [build|install-ssh]

Builds the local macOS Rust crypto configuration:
  --with-rust-crypto --without-openssl --disable-pkcs11 --disable-security-key

Commands:
  build        configure, clean, and build the Rust crypto target set
  install-ssh build, then install only ./ssh to $PREFIX/bin/ssh

Environment:
  PREFIX=PATH  install prefix (default: repo-root/local)
  JOBS=N       parallel make jobs (default: detected CPU count or 4)

The script puts Homebrew GNU sed first in PATH when available. The macOS build
can otherwise pick up a sed that fails inside autoconf's generated config.status
substitution script.
EOF
}

if [ $# -gt 1 ]; then
	usage >&2
	exit 1
fi

mode="${1:-build}"
case "$mode" in
build|install-ssh)
	;;
*)
	usage >&2
	exit 1
	;;
esac

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
prefix="${PREFIX:-$repo_root/local}"

case "$(uname -s)" in
Darwin)
	;;
*)
	echo "this helper is for macOS local Rust crypto builds" >&2
	exit 1
	;;
esac

if [ -x /opt/homebrew/opt/gnu-sed/libexec/gnubin/sed ]; then
	PATH="/opt/homebrew/opt/gnu-sed/libexec/gnubin:$PATH"
	export PATH
	SED=sed
	export SED
elif [ -x /usr/local/opt/gnu-sed/libexec/gnubin/sed ]; then
	PATH="/usr/local/opt/gnu-sed/libexec/gnubin:$PATH"
	export PATH
	SED=sed
	export SED
fi

if command -v sysctl >/dev/null 2>&1; then
	default_jobs="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"
else
	default_jobs=4
fi
JOBS="${JOBS:-$default_jobs}"

cd "$repo_root"

marker="$(sed -n 's/^#define SSH_VERSION_ADDENDUM[[:space:]]*"\(rust-crypto-v[^"]*\)"/\1/p' version.h)"
if [ -z "$marker" ]; then
	echo "could not find SSH_VERSION_ADDENDUM rust-crypto marker in version.h" >&2
	exit 1
fi

echo "==> regenerating configure"
autoreconf

echo "==> configuring Rust crypto build at $prefix"
./configure \
	--prefix="$prefix" \
	--with-rust-crypto \
	--without-openssl \
	--disable-pkcs11 \
	--disable-security-key

echo "==> cleaning stale objects from earlier configure modes"
make clean

echo "==> building Rust crypto target set"
make -j"$JOBS" rust-crypto-build all

version="$(./ssh -V 2>&1)"
case "$version" in
*"$marker"*)
	;;
*)
	echo "built ./ssh does not report $marker: $version" >&2
	exit 1
	;;
esac
printf '%s\n' "$version"

if [ "$mode" = "install-ssh" ]; then
	echo "==> installing only ssh to $prefix/bin/ssh"
	mkdir -p "$prefix/bin"
	${INSTALL:-install} -c -m 0755 ssh "$prefix/bin/ssh"
	installed_version="$("$prefix/bin/ssh" -V 2>&1)"
	case "$installed_version" in
	*"$marker"*)
		;;
	*)
		echo "$prefix/bin/ssh does not report $marker: $installed_version" >&2
		exit 1
		;;
	esac
	printf '%s\n' "$installed_version"
fi
