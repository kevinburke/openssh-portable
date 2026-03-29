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
	echo "==> building missing Docker image openssh-ci-repro"
	docker build -t openssh-ci-repro -f docker/ci-repro.Dockerfile .
fi
if ! docker image inspect openssh-ci-repro-ubuntu22 >/dev/null 2>&1; then
	echo "==> building missing Docker image openssh-ci-repro-ubuntu22"
	docker build --build-arg UBUNTU_VERSION=22.04 \
		-t openssh-ci-repro-ubuntu22 -f docker/ci-repro.Dockerfile .
fi

echo "==> cargo test"
cargo test --manifest-path rust/crypto/Cargo.toml

echo "==> docker rust-crypto unit"
docker run --rm -v "$repo_root:/src" -w /src openssh-ci-repro \
	env MAKE_TARGETS=unit ./contrib/ci-repro.sh rust-crypto

echo "==> docker default unit"
docker run --rm -v "$repo_root:/src" -w /src openssh-ci-repro \
	env MAKE_TARGETS=unit ./contrib/ci-repro.sh default

echo "==> docker openssl-noec unit"
docker run --rm -v "$repo_root:/src" -w /src openssh-ci-repro \
	env MAKE_TARGETS=unit ./contrib/ci-repro.sh openssl-noec

echo "==> docker without-openssl unit"
docker run --rm -v "$repo_root:/src" -w /src openssh-ci-repro \
	env MAKE_TARGETS=unit ./contrib/ci-repro.sh without-openssl

echo "==> docker gcc-12-Werror unit"
docker run --rm -v "$repo_root:/src" -w /src openssh-ci-repro-ubuntu22 \
	env MAKE_TARGETS=unit ./contrib/ci-repro.sh gcc-12-Werror

ltests="$(./contrib/select-rust-ltests.sh)"
if [ -n "$ltests" ]; then
	echo "==> docker rust-crypto t-exec ($ltests)"
	docker run --rm -v "$repo_root:/src" -w /src openssh-ci-repro \
		env MAKE_TARGETS=t-exec LTESTS="$ltests" ./contrib/ci-repro.sh rust-crypto
fi
