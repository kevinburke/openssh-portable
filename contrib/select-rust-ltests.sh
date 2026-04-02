#!/bin/sh

set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"

cd "$repo_root"

tmp="${TMPDIR:-/tmp}/select-rust-ltests.$$"
paths_tmp="${TMPDIR:-/tmp}/select-rust-ltests-paths.$$"
trap 'rm -f "$tmp" "$paths_tmp"' EXIT INT TERM

collect_changed_paths() {
	if git rev-parse --verify '@{push}' >/dev/null 2>&1; then
		git diff --name-only '@{push}..HEAD'
	else
		git diff --name-only HEAD~8..HEAD 2>/dev/null || git diff --name-only HEAD
	fi
	git diff --name-only
	git diff --name-only --cached
}

add_test() {
	test_name="$1"
	if ! grep -Fx "$test_name" "$tmp" >/dev/null 2>&1; then
		printf '%s\n' "$test_name" >>"$tmp"
	fi
}

: >"$tmp"
collect_changed_paths >"$paths_tmp"

# Always keep one focused transport smoke test in the pre-push gate.
add_test rekey

while IFS= read -r path; do
	[ -n "$path" ] || continue
	case "$path" in
	regress/dhgex.sh|dh.c|kexdh.c|kexdh-rust.c|kexgex.c|kexgexc.c|kexgexs.c|kexgex-rust.c|moduli.c|rust/crypto/src/dh.rs)
		add_test dhgex
		add_test rekey
		;;
	cipher.c|cipher-*.c|mac.c|hmac.c|packet.c|digest-rust.c|rust/crypto/src/cipher.rs|rust/crypto/src/digest.rs)
		add_test try-ciphers
		add_test keygen-knownhosts
		add_test rekey
		;;
	readconf.c|misc.c|servconf.c|auth-options.c|rust/crypto/src/util.rs)
		add_test cfgparse
		add_test forwarding
		add_test connect-uri
		;;
	sshkey.c|authfile.c|authfd.c|hostfile.c|ssh-add.c|ssh-agent.c|ssh-ecdsa*.c|ssh-rsa*.c|ssh-ed25519*.c|rust/crypto/src/ecdsa.rs|rust/crypto/src/rsa.rs|rust/crypto/src/openssh_key.rs|rust/crypto/src/private_pem.rs|rust/crypto/src/cert.rs|rust/crypto/src/sshkey_meta.rs)
		add_test agent
		add_test keygen-comment
		add_test keygen-convert
		add_test keygen-sshfp
		add_test keyscan
		;;
	regress/*.sh)
		test_name="${path##*/}"
		test_name="${test_name%.sh}"
		case "$test_name" in
		""|mktests|valgrind-unit|test-exec|agent-ca.pub|*.pub)
			;;
		*)
			add_test "$test_name"
			;;
		esac
		;;
	esac
done <"$paths_tmp"

tr '\n' ' ' <"$tmp" | sed 's/ $//'
