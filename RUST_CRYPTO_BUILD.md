# Building in Rust Crypto Mode

This tree has an experimental `--with-rust-crypto` build mode.

Today this is Phase 0 plumbing plus backend selection:

- it adds a Rust static library to the build,
- it enables `WITH_RUST_CRYPTO`,
- it reports `Rust crypto backend` in `ssh -V`,
- it does not yet reroute the transport crypto implementations to Rust.

In other words, this is currently a build and integration mode, not full
Rust crypto execution parity.

## Prerequisites

You need:

- a working C toolchain supported by the normal OpenSSH build,
- `cargo`,
- `rustc`,
- `autoconf` and friends if building from git or after changing `configure.ac`.

You can check the Rust toolchain with:

```sh
cargo --version
rustc --version
```

## Recommended clean build

If you are switching from a previous OpenSSL or non-OpenSSL build, start
from a clean tree:

```sh
make distclean
```

If `configure` needs to be regenerated, run:

```sh
autoreconf -fi
```

## Configure and build

The Rust mode currently requires `--without-openssl`:

```sh
./configure --without-openssl --with-rust-crypto
make
```

That is the minimum Rust-mode build.

Note that the `./configure` summary shows the configured install prefix. It
does not install anything onto the host unless you run `make install`.

For local testing, prefer a repo-local prefix:

```sh
./configure \
  --prefix="$PWD/local" \
  --sysconfdir="$PWD/local/etc" \
  --bindir="$PWD/local/bin" \
  --sbindir="$PWD/local/sbin" \
  --libexecdir="$PWD/local/libexec" \
  --without-openssl \
  --with-rust-crypto
make
```

If you do want an install tree for testing, install into that local prefix:

```sh
make install
```

## Recommended no-libcrypto variant

If the goal is to keep helper binaries from pulling `libcrypto` back in
through optional features, disable PKCS#11 and security-key support too:

```sh
./configure \
  --without-openssl \
  --with-rust-crypto \
  --disable-pkcs11 \
  --disable-security-key
make
```

Why this matters:

- PKCS#11 support is separate from the core transport crypto path.
- Built-in FIDO/U2F support may bring in `libfido2`, which may itself link
  against `libcrypto` on some systems.

If you only build with `--without-openssl --with-rust-crypto`, the main
`ssh` binary may still be OpenSSL-free while optional helpers are not.

## Verifying the result

Check that the binary was built in Rust mode:

```sh
./ssh -V
```

Current expected output includes:

```text
OpenSSH_10.2p1, Rust crypto backend
```

You can also inspect linkage:

macOS:

```sh
otool -L ./ssh
```

Linux:

```sh
ldd ./ssh
```

For the stricter variant above, inspect the helper binaries too, especially:

```sh
otool -L ./ssh ./sshd ./ssh-pkcs11-helper ./ssh-sk-helper
```

or on Linux:

```sh
ldd ./ssh ./sshd ./ssh-pkcs11-helper ./ssh-sk-helper
```

## Useful targets

Build just the Rust static library:

```sh
make rust-crypto-build
```

The crate lives at:

- `rust/crypto/Cargo.toml`
- `rust/crypto/src/lib.rs`

The generated static library is placed under:

- `rust/crypto-target/release/librust_crypto.a`
- installed test binaries can be kept under `local/` if you use the local
  prefix above

## Current scope

The intended next steps are described in `RUST_BACKEND_PLAN.md`.

Until those phases land, do not assume that `--with-rust-crypto` means:

- full replacement for libcrypto,
- Rust-backed Ed25519,
- Rust-backed Curve25519,
- Rust-backed digest implementations,
- RSA/ECDSA/PKCS#11 parity.
