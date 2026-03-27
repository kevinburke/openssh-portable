#!/bin/sh

set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"

cd "$repo_root"

if ! command -v docker >/dev/null 2>&1; then
	echo "docker is required for pre-push Rust checks" >&2
	exit 1
fi

if ! docker image inspect openssh-ci-repro >/dev/null 2>&1; then
	echo "missing Docker image: openssh-ci-repro" >&2
	echo "build it with: docker build -t openssh-ci-repro -f docker/ci-repro.Dockerfile ." >&2
	exit 1
fi

echo "==> cargo test"
cargo test --manifest-path rust/crypto/Cargo.toml

echo "==> docker rust-crypto unit"
docker run --rm -v "$repo_root:/src" -w /src openssh-ci-repro \
	env MAKE_TARGETS=unit ./contrib/ci-repro.sh rust-crypto

echo "==> docker openssl-noec unit"
docker run --rm -v "$repo_root:/src" -w /src openssh-ci-repro \
	env MAKE_TARGETS=unit ./contrib/ci-repro.sh openssl-noec

echo "==> docker without-openssl unit"
docker run --rm -v "$repo_root:/src" -w /src openssh-ci-repro \
	env MAKE_TARGETS=unit ./contrib/ci-repro.sh without-openssl

echo "==> docker rust-crypto rekey"
docker run --rm -v "$repo_root:/src" -w /src openssh-ci-repro \
	env MAKE_TARGETS=t-exec LTESTS=rekey ./contrib/ci-repro.sh rust-crypto
