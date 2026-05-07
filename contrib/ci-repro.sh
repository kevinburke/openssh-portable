#!/bin/sh

set -eu

usage() {
	cat <<'EOF'
usage: contrib/ci-repro.sh <config>

Supported configs:
  default
  gcc-12-Werror
  openssl-noec
  without-openssl
  rust-crypto

Environment:
  JOBS=N           parallel make jobs (default: detected or 4)
  WORKDIR=PATH     worktree/build directory (default: /tmp/openssh-ci-<config>)
  KEEP_WORKTREE=1  leave the throwaway worktree behind after the run
  ALLOW_DIRTY_WORKTREE=1  test the current dirty checkout instead of refusing
  MAKE_TARGETS=... override the default make targets for the config
EOF
}

run_make_targets() {
	unit_first=""
	rest=""

	for target in "$@"; do
		if [ "$target" = "unit" ]; then
			unit_first=1
		else
			rest="$rest $target"
		fi
	done

	set -- make -j"$JOBS" TEST_SSH_UNSAFE_PERMISSIONS="$TEST_SSH_UNSAFE_PERMISSIONS"

	if [ -n "${LTESTS:-}" ]; then
		set -- "$@" "LTESTS=${LTESTS}"
	fi
	if [ -n "${LTESTS_FROM:-}" ]; then
		set -- "$@" "LTESTS_FROM=${LTESTS_FROM}"
	fi
	if [ -n "${SKIP_LTESTS:-}" ]; then
		set -- "$@" "SKIP_LTESTS=${SKIP_LTESTS}"
	fi

	if [ -n "$unit_first" ]; then
		printf '==> running make unit\n'
		"$@" unit
	fi
	if [ -n "$rest" ]; then
		printf '==> running make%s\n' "$rest"
		# shellcheck disable=SC2086
		"$@" $rest
	fi
}

if [ $# -ne 1 ]; then
	usage >&2
	exit 1
fi

config="$1"

case "$config" in
default|gcc-12-Werror|openssl-noec|without-openssl|rust-crypto)
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
TEST_SSH_UNSAFE_PERMISSIONS="${TEST_SSH_UNSAFE_PERMISSIONS:-1}"

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
workdir="${WORKDIR:-/tmp/openssh-ci-$config}"
privsep_dir="$workdir/empty"

if [ "${ALLOW_DIRTY_WORKTREE:-0}" != "1" ]; then
	if ! git -C "$repo_root" diff --quiet --ignore-submodules -- . ':(exclude)local'; then
		echo "ci-repro requires a clean worktree; commit or stash changes first" >&2
		exit 1
	fi
	if ! git -C "$repo_root" diff --cached --quiet --ignore-submodules -- . ':(exclude)local'; then
		echo "ci-repro requires a clean index; commit or unstage changes first" >&2
		exit 1
	fi
fi

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

git -C "$repo_root" worktree prune >/dev/null 2>&1 || true

git -C "$repo_root" worktree add --force --detach "$workdir" HEAD
cd "$workdir"
mkdir -p "$privsep_dir"

autoreconf -fi

case "$config" in
default)
	./configure \
	  --prefix="$PWD/local" \
	  --with-privsep-user=root \
	  --with-privsep-path="$privsep_dir"
	make_targets="${MAKE_TARGETS:-unit}"
	;;
gcc-12-Werror)
	CC=gcc-12 \
	CFLAGS="-O2 -Wno-format-truncation -Wimplicit-fallthrough=4 -Wno-unused-parameter -Wno-unused-result" \
	./configure \
	  --prefix="$PWD/local" \
	  --with-pam \
	  --with-Werror \
	  --with-privsep-user=root \
	  --with-privsep-path="$privsep_dir"
	make_targets="${MAKE_TARGETS:-unit}"
	;;
openssl-noec)
	.github/install_libcrypto.sh OpenSSL_1_1_1k /opt/openssl no-ec
	./configure \
	  --prefix="$PWD/local" \
	  --with-ssl-dir=/opt/openssl \
	  --with-rpath=-Wl,-rpath, \
	  --disable-security-key
	make_targets="${MAKE_TARGETS:-unit}"
	;;
without-openssl)
	./configure \
	  --prefix="$PWD/local" \
	  --without-openssl \
	  --with-privsep-user=root \
	  --with-privsep-path="$privsep_dir"
	make_targets="${MAKE_TARGETS:-unit t-exec}"
	;;
rust-crypto)
	./configure \
	  --prefix="$PWD/local" \
	  --without-openssl \
	  --with-rust-crypto \
	  --with-privsep-user=root \
	  --with-privsep-path="$privsep_dir" \
	  --disable-pkcs11 \
	  --disable-security-key
	make_targets="${MAKE_TARGETS:-unit t-exec}"
	;;
esac

printf '==> running %s in %s\n' "$config" "$workdir"

case "$config" in
rust-crypto)
	cargo test --manifest-path rust/crypto/Cargo.toml --locked
	cargo build --manifest-path rust/crypto/fuzz/Cargo.toml --locked
	for target in ed25519_verify ecdh_peer dh_peer ecdsa_parse rsa_parse chachapoly_decrypt config_helpers packet_mac sshkey_metadata sshkey_lifecycle; do
		cargo run --manifest-path rust/crypto/fuzz/Cargo.toml --locked --bin "$target" -- -runs=1
	done
	;;
esac

# shellcheck disable=SC2086
run_make_targets $make_targets
