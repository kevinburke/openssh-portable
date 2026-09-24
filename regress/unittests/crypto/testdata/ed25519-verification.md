# Ed25519 verification compatibility

The shared fixture `ed25519-verification.txt` exercises Rust, OpenSSL, and
OpenSSH's bundled C verifier. It is read by both the Rust tests and the C
`test_crypto` unit test, so the release gate checks all three backends.
Each row records acceptance separately; a difference is not automatically a bug.

## Source and selection

Source: [C2SP/CCTV ed25519vectors](https://github.com/C2SP/CCTV/tree/5ea85644bd035c555900a2f707f7e4c31ea65ced/ed25519vectors),
pinned to commit `5ea85644bd035c555900a2f707f7e4c31ea65ced`.
The accompanying license is retained in `ed25519-verification.LICENSE`.

SHA-256 of the original `ed25519vectors.json`:

```
b38e84caf3e7e89170ff520292dbeae421b0a794c27408ce5ce973018fe3d7f9
```

We compared all 914 vectors, then retained the first vector for each distinct
combination of sorted flags and the three verification outcomes: 69 vectors.
Comments preserve the original flags, and IDs refer to the original dataset.
Messages, public keys, and signatures are hex encoded in the fixture.

## Observed behavior

The September 2026 audit used ed25519-dalek 2.2.0, OpenSSL 3.6.4, and the bundled
`ed25519.c` from upstream commit `ccc26c76cd47ca224ff5e4ef8b96007b65ff0b4e`.

| Rust | Bundled C | OpenSSL | Number of vectors |
| --- | --- | --- | ---: |
| reject | reject | reject | 679 |
| reject | reject | accept | 165 |
| reject | accept | reject | 27 |
| accept | accept | accept | 43 |

These are deliberately crafted edge cases, not a sample of normal signatures.
All three backends also pass the RFC 8032 signing and verification vectors
in `test_ed25519.c`.

Rust retains `verify_strict()`: it rejects small-order public keys and R values,
and requires the verification equation without multiplying by the cofactor.
The bundled C implementation rejects small-order points too, but accepts the
27 additional cases where a low-order residue vanishes under its cofactor
check. OpenSSL accepts some small-order and noncanonical inputs that both
Rust and bundled C reject. The fixture records the exact cases instead of
assuming that all malformed encodings behave alike.

We found no vector accepted by Rust but rejected by another backend. This is
an observation about this corpus, not a proof over all possible signatures.
There is no reason from these results to relax Rust's verification policy.

The C tests also check rejection of noncanonical scalars (`S + L` and a high
scalar bit), and exercise the new detached signing API with a null output
length pointer. Rust tests check changed messages, invalid public keys,
incorrect signature/key lengths, and null nonempty message inputs.

## Running the regression tests

```
cargo test --manifest-path rust/crypto/Cargo.toml --locked ed25519
make regress-prep
make regress/unittests/crypto/test_crypto
./regress/unittests/crypto/test_crypto -d regress/unittests/crypto/testdata
```

Run the C tests in separately configured Rust, default OpenSSL, and
`--without-openssl` builds. `make prepush-rust` covers these configurations
in Docker. These tests use the checked-in fixture and need no vector download.
