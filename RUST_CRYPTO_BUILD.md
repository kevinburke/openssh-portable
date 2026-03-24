# Building in Rust Crypto Mode

This tree has an experimental `--with-rust-crypto` build mode.

Today this is beyond Phase 0 plumbing: several real crypto seams are routed
through Rust, but the tree is not yet at full Rust parity for the
`--without-openssl` algorithm set.

## Current Support Matrix

Rust-backed today:

- backend selection and Rust static library linkage
- backend label in `ssh -V`
- SHA-256, SHA-384, and SHA-512 digests
- Ed25519 key generation, signing, and verification
- Curve25519/X25519 key exchange helpers
- NIST ECDH key exchange helpers
  (`ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`, `ecdh-sha2-nistp521`)
- the X25519 portion of the hybrid
  `sntrup761x25519-sha512` and `mlkem768x25519-sha256` KEX paths
- AES-CTR transport cipher (`aes128-ctr`, `aes192-ctr`, `aes256-ctr`)
- ChaCha20-Poly1305 transport cipher (`chacha20-poly1305@openssh.com`)
- standalone Rust fuzz targets for:
  - Ed25519 verification
  - NIST ECDH peer/public input handling
  - ChaCha20-Poly1305 packet decrypt/auth failure handling

Still on the existing C path today:

- MD5 and SHA1 digest support
- SNTRUP761 KEM code
- MLKEM768 KEM code
- RSA
- ECDSA
- classic finite-field DH / DH-GEX
- PKCS#11 and security-key code paths

In other words, this is now a mixed Rust/C crypto build, not yet a
full-Rust transport/backend replacement.

## Rust Dependency Inventory

Rust's standard library does not provide the cryptographic primitives this
backend needs. `std` gives us the usual systems pieces like memory handling,
FFI, and OS integration, but not SSH transport or public-key crypto
implementations. These crates were chosen because they map closely to the
algorithms OpenSSH already uses in the `--without-openssl` configuration and
because they are focused, pure-Rust implementations instead of wrappers
around OpenSSL.

| Crate | Why it is here | Source | Releases |
| --- | --- | --- | --- |
| `aes` | AES block primitive used by the Rust AES-CTR transport path | <https://github.com/RustCrypto/block-ciphers> | <https://crates.io/crates/aes> |
| `poly1305` | Poly1305 authenticator used by the Rust `chacha20-poly1305@openssh.com` transport path | <https://github.com/RustCrypto/universal-hashes> | <https://crates.io/crates/poly1305> |
| `ed25519-dalek` | Ed25519 key generation, signing, and verification | <https://github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek> | <https://crates.io/crates/ed25519-dalek> |
| `x25519-dalek` | X25519 key exchange for `curve25519-sha256*` and the X25519 half of hybrid KEX | <https://github.com/dalek-cryptography/curve25519-dalek/tree/main/x25519-dalek> | <https://crates.io/crates/x25519-dalek> |
| `p256` | NIST P-256 ECDH support for the Rust `ecdh-sha2-nistp256` KEX path | <https://github.com/RustCrypto/elliptic-curves/tree/master/p256> | <https://crates.io/crates/p256> |
| `p384` | NIST P-384 ECDH support for the Rust `ecdh-sha2-nistp384` KEX path | <https://github.com/RustCrypto/elliptic-curves/tree/master/p384> | <https://crates.io/crates/p384> |
| `p521` | NIST P-521 ECDH support for the Rust `ecdh-sha2-nistp521` KEX path | <https://github.com/RustCrypto/elliptic-curves/tree/master/p521> | <https://crates.io/crates/p521> |
| `rand_core` | OS randomness for ephemeral key generation in the Rust ECDH path | <https://github.com/rust-random/rand> | <https://crates.io/crates/rand_core> |
| `arbitrary` | Structured fuzz inputs for the Rust fuzz targets | <https://github.com/rust-fuzz/arbitrary> | <https://crates.io/crates/arbitrary> |
| `libfuzzer-sys` | libFuzzer integration for the Rust fuzz targets | <https://github.com/rust-fuzz/libfuzzer> | <https://crates.io/crates/libfuzzer-sys> |

## CI coverage

The `rust-crypto` GitHub Actions job exercises the Rust backend directly.
Today it runs:

- `cargo test --manifest-path rust/crypto/Cargo.toml`
- `cargo build --manifest-path rust/crypto/fuzz/Cargo.toml`
- `cargo run --manifest-path rust/crypto/fuzz/Cargo.toml --bin ed25519_verify -- -runs=1`
- the OpenSSH `unit` and `t-exec` targets under `--with-rust-crypto`

That gives both Rust-native coverage and OpenSSH integration coverage in CI.

## Test commands

The main local test commands for the current branch are:

Rust unit and property tests:

```sh
cargo test --manifest-path rust/crypto/Cargo.toml
```

OpenSSH unit tests in Rust mode:

```sh
make unit
```

OpenSSH integration/regress tests in Rust mode:

```sh
make t-exec
```

Or run the same pair CI uses in the Rust job:

```sh
make unit t-exec
```

If you want to rebuild only the Rust static library and the common test
binaries first:

```sh
make rust-crypto-build ssh sshd ssh-keygen
```

On this branch, the Rust unit tests include both fixed vectors and
randomized/property-style checks for digests, Ed25519, X25519, NIST ECDH,
AES-CTR, and ChaCha20-Poly1305.

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

## Validation commands

The quickest real smoke tests for the current branch are forced handshakes
against a server that already accepts Ed25519 user auth and offers an
Ed25519 host key.

Plain Curve25519 plus Rust-backed transport ciphers:

```sh
./ssh -v \
  -oBatchMode=yes \
  -oConnectTimeout=10 \
  -oKexAlgorithms=curve25519-sha256 \
  -oHostKeyAlgorithms=ssh-ed25519 \
  -oPubkeyAcceptedAlgorithms=ssh-ed25519 \
  -c aes128-ctr \
  -i ~/.ssh/id_ed25519 \
  user@host true

./ssh -v \
  -oBatchMode=yes \
  -oConnectTimeout=10 \
  -oKexAlgorithms=curve25519-sha256 \
  -oHostKeyAlgorithms=ssh-ed25519 \
  -oPubkeyAcceptedAlgorithms=ssh-ed25519 \
  -c aes192-ctr \
  -i ~/.ssh/id_ed25519 \
  user@host true

./ssh -v \
  -oBatchMode=yes \
  -oConnectTimeout=10 \
  -oKexAlgorithms=curve25519-sha256 \
  -oHostKeyAlgorithms=ssh-ed25519 \
  -oPubkeyAcceptedAlgorithms=ssh-ed25519 \
  -c aes256-ctr \
  -i ~/.ssh/id_ed25519 \
  user@host true

./ssh -v \
  -oBatchMode=yes \
  -oConnectTimeout=10 \
  -oKexAlgorithms=curve25519-sha256 \
  -oHostKeyAlgorithms=ssh-ed25519 \
  -oPubkeyAcceptedAlgorithms=ssh-ed25519 \
  -c chacha20-poly1305@openssh.com \
  -i ~/.ssh/id_ed25519 \
  user@host true
```

To exercise the Rust-backed NIST ECDH paths:

```sh
./ssh -v \
  -oBatchMode=yes \
  -oConnectTimeout=10 \
  -oKexAlgorithms=ecdh-sha2-nistp256 \
  -oHostKeyAlgorithms=ssh-ed25519 \
  -oPubkeyAcceptedAlgorithms=ssh-ed25519 \
  -i ~/.ssh/id_ed25519 \
  user@host true

./ssh -v \
  -oBatchMode=yes \
  -oConnectTimeout=10 \
  -oKexAlgorithms=ecdh-sha2-nistp384 \
  -oHostKeyAlgorithms=ssh-ed25519 \
  -oPubkeyAcceptedAlgorithms=ssh-ed25519 \
  -i ~/.ssh/id_ed25519 \
  user@host true

./ssh -v \
  -oBatchMode=yes \
  -oConnectTimeout=10 \
  -oKexAlgorithms=ecdh-sha2-nistp521 \
  -oHostKeyAlgorithms=ssh-ed25519 \
  -oPubkeyAcceptedAlgorithms=ssh-ed25519 \
  -i ~/.ssh/id_ed25519 \
  user@host true
```

To exercise the Rust-backed X25519 helper through the hybrid KEX paths:

```sh
./ssh -v \
  -oBatchMode=yes \
  -oConnectTimeout=10 \
  -oKexAlgorithms=sntrup761x25519-sha512 \
  -oHostKeyAlgorithms=ssh-ed25519 \
  -oPubkeyAcceptedAlgorithms=ssh-ed25519 \
  -i ~/.ssh/id_ed25519 \
  user@host true

./ssh -v \
  -oBatchMode=yes \
  -oConnectTimeout=10 \
  -oKexAlgorithms=mlkem768x25519-sha256 \
  -oHostKeyAlgorithms=ssh-ed25519 \
  -oPubkeyAcceptedAlgorithms=ssh-ed25519 \
  -i ~/.ssh/id_ed25519 \
  user@host true
```

The important lines to look for are:

- `OpenSSH_10.2p1, Rust crypto backend`
- `kex: algorithm: ...`
- `server->client cipher: ...`
- `client->server cipher: ...`
- `Authenticated to ... using "publickey".`
- `Exit status 0`

## Rust fuzzing

The Rust crate now has standalone libFuzzer targets under `rust/crypto/fuzz`.

Build all fuzz targets:

```sh
cargo build --manifest-path rust/crypto/fuzz/Cargo.toml
```

For real coverage-guided fuzzing, install `cargo-fuzz` and use nightly:

```sh
cargo install cargo-fuzz
```

Run a short smoke test:

```sh
cargo run --manifest-path rust/crypto/fuzz/Cargo.toml \
  --bin ed25519_verify -- -runs=1
```

Run a bounded real fuzzing session:

```sh
cd rust/crypto/fuzz
cargo +nightly fuzz run ed25519_verify -- -max_total_time=60
cargo +nightly fuzz run ecdh_peer -- -max_total_time=60
cargo +nightly fuzz run chachapoly_decrypt -- -max_total_time=60
```

Run a longer local fuzzing session:

```sh
cd rust/crypto/fuzz
cargo +nightly fuzz run chachapoly_decrypt
```

Current targets:

- `ed25519_verify`
- `ecdh_peer`
- `chachapoly_decrypt`

Notes:

- the CI job only does a smoke run of `ed25519_verify`
- `cargo run` is fine for a quick execute/build sanity check
- `cargo +nightly fuzz run ...` is the real coverage-guided path

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
- Rust-backed RSA or ECDSA,
- Rust-backed PKCS#11 or security-key support,
- full Rust transport cipher coverage,
- feature parity with the default OpenSSL build.
