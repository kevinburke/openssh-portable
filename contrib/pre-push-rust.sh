#!/bin/sh

set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"

cd "$repo_root"

if ! git diff --quiet --ignore-submodules -- . ':(exclude)local'; then
	echo "prepush-rust requires a clean worktree; commit or stash changes first" >&2
	exit 1
fi
if ! git diff --cached --quiet --ignore-submodules -- . ':(exclude)local'; then
	echo "prepush-rust requires a clean index; commit or unstage changes first" >&2
	exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
	echo "docker is required for pre-push Rust checks" >&2
	exit 1
fi

# Distinguish an unavailable daemon from a missing image.
docker info >/dev/null

# Linked worktrees contain absolute paths into the common Git directory.
# Preserve both paths inside Docker so ci-repro can create its worktree.
git_common_dir="$(git rev-parse --path-format=absolute --git-common-dir)"
run_docker() {
	docker run --rm --volume "$repo_root:$repo_root" \
	    --volume "$git_common_dir:$git_common_dir" \
	    --workdir "$repo_root" "$@"
}

if ! docker image inspect openssh-ci-repro >/dev/null 2>&1; then
	echo "==> building missing Docker image openssh-ci-repro"
	docker build -t openssh-ci-repro -f docker/ci-repro.Dockerfile .
fi
if ! docker image inspect openssh-ci-repro-ubuntu22 >/dev/null 2>&1; then
	echo "==> building missing Docker image openssh-ci-repro-ubuntu22"
	docker build --build-arg UBUNTU_VERSION=22.04 \
		-t openssh-ci-repro-ubuntu22 -f docker/ci-repro.Dockerfile .
fi

echo "==> cargo fmt"
cargo fmt --manifest-path rust/crypto/Cargo.toml --check

echo "==> production panic boundaries"
python3 rust/crypto/check-no-production-panics.py

echo "==> cargo test"
cargo test --manifest-path rust/crypto/Cargo.toml --locked

echo "==> docker rust-crypto unit"
run_docker openssh-ci-repro \
	env MAKE_TARGETS=unit ./contrib/ci-repro.sh rust-crypto

echo "==> docker default unit"
run_docker openssh-ci-repro \
	env MAKE_TARGETS=unit ./contrib/ci-repro.sh default

echo "==> docker without-openssl unit"
run_docker openssh-ci-repro \
	env MAKE_TARGETS=unit ./contrib/ci-repro.sh without-openssl

echo "==> docker gcc-12-Werror unit"
run_docker openssh-ci-repro-ubuntu22 \
	env MAKE_TARGETS=unit ./contrib/ci-repro.sh gcc-12-Werror

ltests="$(./contrib/select-rust-ltests.sh)"
if [ -n "$ltests" ]; then
	echo "==> docker rust-crypto t-exec ($ltests)"
	run_docker openssh-ci-repro \
		env MAKE_TARGETS=t-exec LTESTS="$ltests" ./contrib/ci-repro.sh rust-crypto
fi
