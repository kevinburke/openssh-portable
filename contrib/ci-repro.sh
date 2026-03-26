#!/bin/sh

set -eu

usage() {
	cat <<'EOF'
usage: contrib/ci-repro.sh <config>

Supported configs:
  openssl-noec
  rust-crypto

Environment:
  JOBS=N           parallel make jobs (default: detected or 4)
  WORKDIR=PATH     worktree/build directory (default: /tmp/openssh-ci-<config>)
  KEEP_WORKTREE=1  leave the throwaway worktree behind after the run
  MAKE_TARGETS=... override the default make targets for the config
EOF
}

if [ $# -ne 1 ]; then
	usage >&2
	exit 1
fi

config="$1"

case "$config" in
openssl-noec|rust-crypto)
	;;
*)
	echo "unsupported config: $config" >&2
	usage >&2
	exit 1
	;;
esac

if command -v nproc >/dev/null 2>&1; then
	default_jobs="$(nproc)"
else
	default_jobs=4
fi
JOBS="${JOBS:-$default_jobs}"

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
workdir="${WORKDIR:-/tmp/openssh-ci-$config}"

cleanup() {
	if [ "${KEEP_WORKTREE:-0}" = "1" ]; then
		return
	fi
	if [ -d "$workdir/.git" ] || [ -f "$workdir/.git" ]; then
		git -C "$repo_root" worktree remove --force "$workdir" >/dev/null 2>&1 || true
	else
		rm -rf "$workdir"
	fi
}
trap cleanup EXIT INT TERM

if [ -e "$workdir" ]; then
	rm -rf "$workdir"
fi

git -C "$repo_root" worktree add --detach "$workdir" HEAD
cd "$workdir"

autoreconf -fi

case "$config" in
openssl-noec)
	.github/install_libcrypto.sh OpenSSL_1_1_1k /opt/openssl no-ec
	./configure \
	  --prefix="$PWD/local" \
	  --with-ssl-dir=/opt/openssl \
	  --with-rpath=-Wl,-rpath, \
	  --disable-security-key
	make_targets="${MAKE_TARGETS:-unit}"
	;;
rust-crypto)
	./configure \
	  --prefix="$PWD/local" \
	  --without-openssl \
	  --with-rust-crypto \
	  --disable-pkcs11 \
	  --disable-security-key
	make_targets="${MAKE_TARGETS:-unit t-exec}"
	;;
esac

printf '==> running %s in %s\n' "$config" "$workdir"

case "$config" in
rust-crypto)
	cargo test --manifest-path rust/crypto/Cargo.toml
	cargo build --manifest-path rust/crypto/fuzz/Cargo.toml
	cargo run --manifest-path rust/crypto/fuzz/Cargo.toml --bin ed25519_verify -- -runs=1
	cargo run --manifest-path rust/crypto/fuzz/Cargo.toml --bin dh_peer -- -runs=1
	cargo run --manifest-path rust/crypto/fuzz/Cargo.toml --bin ecdsa_parse -- -runs=1
	cargo run --manifest-path rust/crypto/fuzz/Cargo.toml --bin rsa_parse -- -runs=1
	;;
esac

make -j"$JOBS" $make_targets
