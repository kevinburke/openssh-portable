#!/bin/sh

set -eu

usage() {
	cat <<'EOF'
usage: contrib/bench-rust-crypto.sh [quick|full]

Builds two throwaway worktrees from the current HEAD:
  - default/OpenSSL
  - Rust crypto (--without-openssl --with-rust-crypto)

Then runs selected in-tree unit benchmarks and records:
  - benchmark throughput from the unit test harness
  - wall/user/sys time
  - max RSS when available from /usr/bin/time

Environment:
  JOBS=N           parallel make jobs (default: detected or 4)
  WORK_BASE=PATH   base dir for throwaway worktrees (default: /tmp/openssh-bench)
  KEEP_WORKTREES=1 leave the worktrees/logs in place after the run
EOF
}

if [ $# -gt 1 ]; then
	usage >&2
	exit 1
fi

mode="${1:-quick}"
case "$mode" in
quick|full)
	;;
*)
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
work_base="${WORK_BASE:-/tmp/openssh-bench}"
openssl_dir="$work_base/openssl"
rust_dir="$work_base/rust"
logs_dir="$work_base/logs"

cleanup() {
	if [ "${KEEP_WORKTREES:-0}" = "1" ]; then
		return
	fi
	git -C "$repo_root" worktree remove --force "$openssl_dir" >/dev/null 2>&1 || true
	git -C "$repo_root" worktree remove --force "$rust_dir" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

mkdir -p "$work_base" "$logs_dir"

time_mode() {
	tmp="$work_base/.time-check.$$"
	if /usr/bin/time -l true >/dev/null 2>"$tmp"; then
		rm -f "$tmp"
		echo mac
		return
	fi
	if /usr/bin/time -v true >/dev/null 2>"$tmp"; then
		rm -f "$tmp"
		echo gnu
		return
	fi
	rm -f "$tmp"
	echo posix
}

TIME_MODE="$(time_mode)"

prepare_tree() {
	dir="$1"
	rm -rf "$dir"
	git -C "$repo_root" worktree prune >/dev/null 2>&1 || true
	git -C "$repo_root" worktree add --force --detach "$dir" HEAD >/dev/null
}

configure_tree() {
	label="$1"
	dir="$2"
	shift 2

	(
		cd "$dir"
		autoreconf -fi >/dev/null
		./configure --prefix="$dir/local" "$@" >/dev/null
		make -j"$JOBS" \
			regress/unittests/sshkey/test_sshkey \
			regress/unittests/kex/test_kex >/dev/null
	)
	printf 'prepared %s build in %s\n' "$label" "$dir"
}

extract_bench_line() {
	file="$1"
	sed -n '/^[^ ].*[0-9][0-9]*\.[0-9][0-9] .*\/s$/p' "$file" | tail -n 1
}

extract_time_summary() {
	file="$1"
	case "$TIME_MODE" in
	mac)
		line="$(grep ' real ' "$file" | tail -n 1 || true)"
		rss="$(awk '/maximum resident set size/{print $1}' "$file" | tail -n 1)"
		if [ -n "$line" ]; then
			real="$(printf '%s\n' "$line" | awk '{print $1}')"
			user="$(printf '%s\n' "$line" | awk '{print $3}')"
			sys="$(printf '%s\n' "$line" | awk '{print $5}')"
			printf 'wall=%ss user=%ss sys=%ss maxrss=%s\n' \
				"$real" "$user" "$sys" "${rss:-n/a}"
		else
			printf 'time-summary-unavailable\n'
		fi
		;;
	gnu)
		wall="$(awk -F': ' '/Elapsed \\(wall clock\\) time/{print $2}' "$file" | tail -n 1)"
		user="$(awk -F': ' '/User time \\(seconds\\)/{print $2}' "$file" | tail -n 1)"
		sys="$(awk -F': ' '/System time \\(seconds\\)/{print $2}' "$file" | tail -n 1)"
		rss="$(awk -F': ' '/Maximum resident set size \\(kbytes\\)/{print $2}' "$file" | tail -n 1)"
		printf 'wall=%s user=%ss sys=%ss maxrss=%sKB\n' \
			"${wall:-n/a}" "${user:-n/a}" "${sys:-n/a}" "${rss:-n/a}"
		;;
	*)
		line="$(grep ' real$' "$file" | tail -n 1 || true)"
		if [ -n "$line" ]; then
			real="$(printf '%s\n' "$line" | awk '{print $1}')"
			user="$(printf '%s\n' "$line" | awk '{print $3}')"
			sys="$(printf '%s\n' "$line" | awk '{print $5}')"
			printf 'wall=%ss user=%ss sys=%ss\n' "$real" "$user" "$sys"
		else
			printf 'time-summary-unavailable\n'
		fi
		;;
	esac
}

run_one() {
	label="$1"
	dir="$2"
	binary="$3"
	pattern="$4"
	tag="$5"
	stdout_log="$logs_dir/$tag.$label.out"
	stderr_log="$logs_dir/$tag.$label.time"

	printf '\n[%s] %s\n' "$label" "$pattern"
	(
		cd "$dir"
		case "$TIME_MODE" in
		mac)
			/usr/bin/time -l "$binary" -b -O "$pattern" >"$stdout_log" 2>"$stderr_log"
			;;
		gnu)
			/usr/bin/time -v "$binary" -b -O "$pattern" >"$stdout_log" 2>"$stderr_log"
			;;
		*)
			/usr/bin/time -p "$binary" -b -O "$pattern" >"$stdout_log" 2>"$stderr_log"
			;;
		esac
	)
	printf '  bench: %s\n' "$(extract_bench_line "$stdout_log")"
	printf '  usage: %s\n' "$(extract_time_summary "$stderr_log")"
}

prepare_tree "$openssl_dir"
prepare_tree "$rust_dir"

configure_tree openssl "$openssl_dir" \
	--disable-security-key
configure_tree rust "$rust_dir" \
	--without-openssl \
	--with-rust-crypto \
	--disable-pkcs11 \
	--disable-security-key

run_one openssl "$openssl_dir" ./regress/unittests/sshkey/test_sshkey "generate ED25519" sshkey-generate-ed25519
run_one rust    "$rust_dir"    ./regress/unittests/sshkey/test_sshkey "generate ED25519" sshkey-generate-ed25519
run_one openssl "$openssl_dir" ./regress/unittests/sshkey/test_sshkey "ED25519" sshkey-ed25519
run_one rust    "$rust_dir"    ./regress/unittests/sshkey/test_sshkey "ED25519" sshkey-ed25519
run_one openssl "$openssl_dir" ./regress/unittests/kex/test_kex "KEX curve25519-sha256" kex-curve25519
run_one rust    "$rust_dir"    ./regress/unittests/kex/test_kex "KEX curve25519-sha256" kex-curve25519
run_one openssl "$openssl_dir" ./regress/unittests/kex/test_kex "KEX diffie-hellman-group-exchange-sha256" kex-dhgex
run_one rust    "$rust_dir"    ./regress/unittests/kex/test_kex "KEX diffie-hellman-group-exchange-sha256" kex-dhgex

if [ "$mode" = "full" ]; then
	run_one openssl "$openssl_dir" ./regress/unittests/sshkey/test_sshkey "RSA-2048/SHA256" sshkey-rsa2048-sha256
	run_one rust    "$rust_dir"    ./regress/unittests/sshkey/test_sshkey "RSA-2048/SHA256" sshkey-rsa2048-sha256
	run_one openssl "$openssl_dir" ./regress/unittests/sshkey/test_sshkey "ECDSA-256" sshkey-ecdsa256
	run_one rust    "$rust_dir"    ./regress/unittests/sshkey/test_sshkey "ECDSA-256" sshkey-ecdsa256
	run_one openssl "$openssl_dir" ./regress/unittests/kex/test_kex "KEX ecdh-sha2-nistp256" kex-ecdh-p256
	run_one rust    "$rust_dir"    ./regress/unittests/kex/test_kex "KEX ecdh-sha2-nistp256" kex-ecdh-p256
	run_one openssl "$openssl_dir" ./regress/unittests/kex/test_kex "KEX diffie-hellman-group14-sha256" kex-group14
	run_one rust    "$rust_dir"    ./regress/unittests/kex/test_kex "KEX diffie-hellman-group14-sha256" kex-group14
fi

printf '\nraw logs saved in %s\n' "$logs_dir"
