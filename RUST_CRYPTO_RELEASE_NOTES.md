# rust-crypto-v0.1.9

Rust crypto backend fork based on OpenSSH 10.5p1.

## Changes

- Rebase the Rust backend integration onto upstream OpenSSH 10.5, including
  adaptations for the detached Ed25519 API, fractional timeouts, algorithm
  restrictions, and configuration parsing and output.
- Add `mlkem768nistp256-sha256` using ML-KEM-768 and NIST P-256, including
  client and server support, session-state restoration, and rekeying.
  The default key-exchange preference order is unchanged.
- Audit 914 Ed25519 edge-case vectors against Rust, OpenSSL, and bundled C.
  Preserve Rust's strict verification policy and retain 69 representative
  vectors as shared regression tests. The implementations intentionally
  differ on some edge cases; ordinary known-answer signatures pass on all.
- Update release checks for upstream's required OpenSSL elliptic-curve
  support, linked worktrees, formatting, and panic boundaries. Add hybrid
  key-exchange fuzz smoke coverage and forced-algorithm integration tests.

## Validation

- 214 Rust tests pass on macOS and Linux.
- The full Docker release gate passes for Rust, OpenSSL, bundled C, and
  GCC 12 with warnings treated as errors, plus 12 SSH integration tests.
- ML-KEM/P-256 login and rekeying pass with Rust at both ends and in both
  Rust/OpenSSL client/server combinations.
- Independent hybrid known-answer tests cover a leading-zero ECDH secret.
  Negative tests cover malformed points and lengths, noncanonical KEM keys,
  implicit ciphertext rejection, and ephemeral-key cleanup.

## Building

This is a source release. See [the build guide](RUST_CRYPTO_BUILD.md) for
platform dependencies, build instructions, and supported functionality.
The source checkout needs `autoreconf` before `./configure`.

The Rust build reports:

```
OpenSSH_10.5p1 rust-crypto-v0.1.9, Rust crypto backend
```
