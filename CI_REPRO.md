# Reproducing CI Locally with Docker

These commands are for reproducing problematic GitHub Actions jobs inside a
Linux container instead of trying to mirror them directly on macOS.

The two most useful cases for this branch are:

- `default`
- `openssl-noec`
- `without-openssl`
- `rust-crypto`
- `gcc-12-Werror` on Ubuntu 22.04

All examples assume you start from the `openssh-portable/` repo root.

If you want the shortest path, use the provided Dockerfile and helper script:

```sh
docker build -t openssh-ci-repro -f docker/ci-repro.Dockerfile .

docker build --build-arg UBUNTU_VERSION=22.04 \
  -t openssh-ci-repro-ubuntu22 -f docker/ci-repro.Dockerfile .
docker run --rm -it -v "$PWD:/src" -w /src openssh-ci-repro \
  ./contrib/ci-repro.sh openssl-noec
```

or:

```sh
docker run --rm -it -v "$PWD:/src" -w /src openssh-ci-repro \
  ./contrib/ci-repro.sh without-openssl
```

or:

```sh
docker run --rm -it -v "$PWD:/src" -w /src openssh-ci-repro \
  ./contrib/ci-repro.sh default

docker run --rm -it -v "$PWD:/src" -w /src openssh-ci-repro \
  ./contrib/ci-repro.sh rust-crypto

docker run --rm -it -v "$PWD:/src" -w /src openssh-ci-repro-ubuntu22 \
  ./contrib/ci-repro.sh gcc-12-Werror
```

The helper script creates a throwaway worktree, configures the requested CI
shape, and runs the matching build/test commands.

For container-only repro convenience, the helper also:

- sets `TEST_SSH_UNSAFE_PERMISSIONS=1`
- configures `--with-privsep-user=root` for `without-openssl` and `rust-crypto`
- configures `--with-privsep-path` to a throwaway directory inside the worktree
- runs `make unit` first as a separate step whenever `MAKE_TARGETS` includes
  `unit`, so it exits before `t-exec` if the fast unit gate fails

That keeps `t-exec` working in a minimal Docker image without needing to add
an `sshd` account, create `/var/empty`, or change `/tmp` permissions by hand.

## Container Setup

Start an Ubuntu 24.04 container with the repo bind-mounted at `/src`:

```sh
docker run --rm -it \
  -v "$PWD:/src" \
  -w /src \
  ubuntu:24.04 \
  bash
```

Inside the container, install a basic CI-like toolchain:

```sh
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  autoconf \
  automake \
  build-essential \
  ca-certificates \
  cargo \
  git \
  libfido2-dev \
  libpam0g-dev \
  libtool \
  mandoc \
  pkg-config \
  zlib1g-dev
```

Create a throwaway worktree inside the container so you can switch configs
without disturbing the main checkout:

```sh
git worktree add --detach /tmp/openssh-ci HEAD
cd /tmp/openssh-ci
autoreconf -fi
```

## Reproducing `default`

This config gives you a cheap baseline OpenSSL build on Ubuntu with the normal
default configuration and `unit` coverage.

```sh
docker run --rm -it -v "$PWD:/src" -w /src openssh-ci-repro \
  ./contrib/ci-repro.sh default
```

To keep it fast and match the pre-push gate:

```sh
docker run --rm -it -v "$PWD:/src" -w /src openssh-ci-repro \
  env MAKE_TARGETS=unit ./contrib/ci-repro.sh default
```

## Reproducing `openssl-noec`

This CI job builds OpenSSL `OpenSSL_1_1_1k` with `no-ec`, installs it under
`/opt/openssl`, then runs the normal OpenSSH build against that libcrypto.

If you are using the helper script, this is just:

```sh
./contrib/ci-repro.sh openssl-noec
```

Inside the container:

```sh
cd /tmp/openssh-ci
.github/install_libcrypto.sh OpenSSL_1_1_1k /opt/openssl no-ec
./configure \
  --prefix="$PWD/local" \
  --with-ssl-dir=/opt/openssl \
  --with-rpath=-Wl,-rpath, \
  --disable-security-key
```

To reproduce the sshkey unit that has been failing on this branch:

```sh
make -j1 regress/unittests/sshkey/test_sshkey
./regress/unittests/sshkey/test_sshkey -d regress/unittests/sshkey/testdata
```

To reproduce the full unit target instead:

```sh
make -j1 unit
```

## Reproducing `rust-crypto`

The Rust CI leg does not need custom OpenSSL. It builds in
`--without-openssl --with-rust-crypto` mode and runs both Rust-native and
OpenSSH integration checks.

The Docker repro image installs current stable Rust with `rustup` instead of
using the distro `cargo`, so it stays compatible with the crate set used by
the branch.

If you are using the helper script, this is just:

```sh
./contrib/ci-repro.sh rust-crypto
```

For the fastest feedback loop, run only the unit leg first:

```sh
env MAKE_TARGETS=unit ./contrib/ci-repro.sh rust-crypto
```

Inside the container:

```sh
cd /tmp/openssh-ci
./configure \
  --prefix="$PWD/local" \
  --without-openssl \
  --with-rust-crypto \
  --disable-pkcs11 \
  --disable-security-key
```

Then run the main checks from CI:

```sh
cargo test --manifest-path rust/crypto/Cargo.toml --locked
cargo build --manifest-path rust/crypto/fuzz/Cargo.toml --locked
cargo run --manifest-path rust/crypto/fuzz/Cargo.toml --locked --bin ed25519_verify -- -runs=1
cargo run --manifest-path rust/crypto/fuzz/Cargo.toml --locked --bin dh_peer -- -runs=1
cargo run --manifest-path rust/crypto/fuzz/Cargo.toml --locked --bin ecdsa_parse -- -runs=1
cargo run --manifest-path rust/crypto/fuzz/Cargo.toml --locked --bin rsa_parse -- -runs=1
make -j1 unit
make -j1 t-exec
```

For a faster smoke pass before a longer regress run:

```sh
make -j1 regress/unittests/sshkey/test_sshkey
./regress/unittests/sshkey/test_sshkey -d regress/unittests/sshkey/testdata
make -j1 regress/unittests/misc/test_misc
./regress/unittests/misc/test_misc
```

## Reproducing `without-openssl`

This is the plain no-libcrypto build, without the Rust backend enabled. It is
useful for catching shared `sshkey.c` and parser regressions that only appear
when neither OpenSSL nor Rust crypto is available.

If you are using the helper script, this is just:

```sh
./contrib/ci-repro.sh without-openssl
```

Inside the container:

```sh
cd /tmp/openssh-ci
./configure \
  --prefix="$PWD/local" \
  --without-openssl
```

To reproduce the exact compile failure on this branch:

```sh
make -j1 sshkey.o
```

For a fuller local pass:

```sh
make -j1 unit
make -j1 t-exec
```

## Notes

- If you switch between `openssl-noec` and `rust-crypto`, use a fresh
  worktree or run `make distclean` before reconfiguring.
- Parser and fallback regressions on this branch are often cheapest to debug
  first with:
  - `regress/unittests/sshkey/test_sshkey`
  - `regress/unittests/misc/test_misc`
- The GitHub Actions logic for these jobs lives in:
  - `.github/setup_ci.sh`
  - `.github/configs`
  - `.github/run_test.sh`
