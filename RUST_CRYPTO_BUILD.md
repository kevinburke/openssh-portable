# Building in Rust Crypto Mode

This tree has an experimental `--with-rust-crypto` build mode.

Today this is beyond Phase 0 plumbing: several real crypto seams are routed
through Rust, but the tree is not yet at full Rust parity for the
`--without-openssl` algorithm set.

## Current Support Matrix

Rust-backed today:

- backend selection and Rust static library linkage
- backend label in `ssh -V`
- MD5, SHA-1, SHA-256, SHA-384, and SHA-512 digests
- Ed25519 key generation, signing, and verification
- RSA key generation, signing, verification, and OpenSSH private/public key
  parsing (`ssh-rsa`, `rsa-sha2-256`, `rsa-sha2-512`)
- ECDSA key generation, signing, verification, and host-key parsing
  (`ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`)
- SSH certificate body parsing
- SSH public-key blob parsing for Ed25519, RSA, and ECDSA
- SSH public-key and certificate text-line parsing through `sshkey_read()`:
  - `.pub` and `-cert.pub` files
  - `authorized_keys` / `known_hosts` style key lines after host/option fields
  - `sshsig` key-file consumers and similar text-key entry points
- `known_hosts` / hostfile line-prefix parsing through
  `hostkeys_foreach()` / `hostkeys_foreach_file()`:
  - `@cert-authority` / `@revoked` marker parsing
  - host-list token extraction
  - no-parse key-type token extraction
  - structured invalid-line classification during hostfile iteration
- hashed `known_hosts` matching and hashing:
  - `|1|salt|hash` entry parsing
  - HMAC-SHA1 host matching
  - hashed host re-encoding with existing or fresh salt
- HMAC computation through `ssh_hmac_*`:
  - `known_hosts` SHA-1 host hashing and matching
  - packet HMAC reset/update/final logic used by `mac.c`
  - legacy MD5 / SHA-1 and SHA-2 HMACs layered on Rust-backed digest state
- digest-backed packet MAC dispatch through `mac.c`:
  - HMAC packet-MAC setup/init/compute/check for `hmac-*`
  - sequence-number prefixing and truncated digest handling
  - UMAC / UMAC128 remain in C
- the first `sshkey.c` dispatch-consolidation slice:
  - `keyimpl` selection by type
  - `keyimpl` selection by `(type, nid)`
  - existing C key object allocation/free and function tables remain in place
- OpenSSH `openssh-key-v1` armor and header parsing
- OpenSSH `openssh-key-v1` decrypted private-section parsing for Ed25519,
  RSA, and ECDSA keys:
  - direct Rust-backed final key assembly for supported key types
  - key-material decode
  - cert-prefixed private-key body handling
  - embedded comment extraction
  - deterministic padding validation
- `argv_split()` tokenization used by:
  - client and server config-file option splitting
  - `ProxyCommand` / helper command parsing
  - auth-command and related quoted-argument consumers
- `strdelim()` / `strdelimw()` tokenization used by:
  - client and server config-file line splitting
  - keyword / argument boundary parsing in `readconf.c` and `servconf.c`
- `hpdelim()` / `hpdelim2()` host-field splitting used by:
  - config-file `host:port` consumers
  - forwarding / permit-open style host-and-port parsing
- `parse_user_host_port()` target parsing used by:
  - `user@host`
  - `host:port`
  - `user@[host]:port`
  - similar destination parsing helpers layered above `hpdelim()`
- `parse_user_host_path()` parsing used by:
  - `user@host:path`
  - `user@[host]:path`
  - similar scp / sftp target parsing helpers
- `parse_uri()` parsing used by:
  - `ssh://[user@]host[:port][/path]`
  - similar `scp://` / `sftp://` style URI entry points
- `parse_forward()` forwarding-spec parsing used by:
  - `LocalForward`, `RemoteForward`, and `DynamicForward`
  - `-L`, `-R`, and `-D` forwarding specifications
  - bracketed literal forwarding fields, escaped forwarding tokens, and
    forwarding-shape validation
  - numeric and service-name port resolution for forwarding endpoints
- `parse_jump()` ProxyJump parsing used by:
  - `ProxyJump`
  - `-J`
  - comma-separated jump-host chains, `ssh://` jump URIs, and `none`
- permit host/port validation used by:
  - `PermitRemoteOpen`
  - `PermitOpen`
  - `PermitListen`
  - bare-port `PermitListen` wildcard forms
- `parse_absolute_time()` parsing used by:
  - certificate validity windows
  - `sshsig` `valid-after` / `valid-before` options
  - `ssh-keygen -V` time parsing
- `convtime()` / `convtime_double()` parsing used by:
  - `ConnectTimeout`, `ForwardX11Timeout`, `ControlPersist`, and similar
    duration-valued config options
  - `ClientAliveInterval` / `UnusedConnectionTimeout` and related server-side
    duration parsing
  - `ChannelTimeout` interval decoding layered above the shared duration parser
- shared config validation helpers used by:
  - `parse_ipqos()` for `IPQoS`
  - `valid_env_name()` for legacy `$ENV` option handling and auth env lists
  - `valid_domain()` for canonical-domain and related hostname validation
  - `atoi_err()` for shared non-negative integer option parsing and
    standardized `missing` / `invalid` / `too small` / `too large` reporting
- shared multistate option lookup used by:
  - repeated client config enums in `readconf.c`
  - repeated server config enums in `servconf.c`
  - case-insensitive matching of `yes`/`no`/`ask`/mode-style config values
- shared multistate option formatting used by:
  - `ssh -G` style client config output
  - `sshd -T` style server config output
  - reverse mapping of enum values back to canonical config strings
- `opt_flag()` parsing used by:
  - `no-pty`, `no-agent-forwarding`, and similar auth-option flags
  - shared config helpers that consume optional `no-` prefixes
  - boolean option fragments that advance the caller input pointer in place
- environment-list lookup helpers used by:
  - `lookup_env_in_list()` for `TERM` and similar inherited `name=value` lookups
  - `lookup_setenv_in_list()` for duplicate-name detection in `SetEnv`
  - shared client/server config handling of `SetEnv`-style lists
- `opt_match()` parsing used by:
  - `command=`, `principals=`, `permitopen=`, and similar auth-option fields
  - `sshsig` option parsing like `namespaces=`, `valid-after=`, and `valid-before=`
  - case-insensitive `name=` matching that advances the caller input pointer
- `opt_dequote()` parsing used by:
  - quoted auth-option values like `command="..."` and `principals="..."`
  - quoted `sshsig` option values like `namespaces="..."`
  - escaped `\"` handling plus shared `missing start/end quote` validation
- shared `%` / `${}` expansion helpers used by:
  - `dollar_expand()` for `${VAR}` expansion with preserved `parseerr` behavior
  - `percent_expand()` for `%h`-style token substitution
  - `percent_dollar_expand()` for mixed `%` and `${VAR}` expansion paths
- client config keyword lookup used by:
  - `readconf.c` option-name parsing before per-option semantics
  - `ssh -G` and normal client config loading
  - exact matching after the existing lowercase normalization step
- server config keyword lookup used by:
  - `servconf.c` option-name parsing before per-option semantics
  - `sshd -T` and normal server config loading
  - case-insensitive keyword matching with existing flag selection preserved
- client config keyword reverse lookup used by:
  - `lookup_opcode_name()` in `readconf.c`
  - `ssh -G` style option-name formatting
- shared config integer formatting used by:
  - `fmt_intarg()` in `readconf.c`
  - `fmt_intarg()` in `servconf.c`
  - `ssh -G` / `sshd -T` style enum and digest-name output formatting
- client forward output formatting used by:
  - `dump_cfg_forwards()` in `readconf.c`
  - `ssh -G` output for `DynamicForward`, `LocalForward`, and `RemoteForward`
  - streamlocal and host/port forward display formatting
- client one-line list formatting used by:
  - `dump_cfg_strarray_oneline()` in `readconf.c`
  - `ssh -G` output for options like `CanonicalDomains` and `PermitRemoteOpen`
  - space-joined list rendering and `none` formatting for empty client lists
- server one-line list formatting used by:
  - `dump_cfg_strarray_oneline()` in `servconf.c`
  - `sshd -T` output for options like `AuthorizedKeysFile`,
    `AuthenticationMethods`, and `ChannelTimeout`
  - space-joined list rendering plus `any` / `none` formatting for the
    server-side empty-list special cases
- shared multi-line list formatting used by:
  - `dump_cfg_strarray()` in `readconf.c` / `servconf.c`
  - `ssh -G` / `sshd -T` output for repeated list-valued options like
    `HostKeyFile`, `IdentityFile`, `AllowUsers`, and `SetEnv`
  - repeated `keyword value` line rendering for client and server config dumps
- shared scalar config string formatting used by:
  - `dump_cfg_string()` in `readconf.c` / `servconf.c`
  - `ssh -G` output for single-value string options
  - `sshd -T` output for single-value string options with `none` fallback
- shared numeric config output formatting used by:
  - `dump_cfg_int()` in `readconf.c` / `servconf.c`
  - `dump_cfg_oct()` in `servconf.c`
  - `ssh -G` / `sshd -T` output for decimal, octal, and special-case `yes` / `no` / `none`
- server `ListenAddress` output formatting used by:
  - `format_listen_addrs()` in `servconf.c`
  - `sshd -T` output for IPv4 and IPv6 listen addresses
  - per-line rendering for `listenaddress ...` output, including bracketed IPv6 formatting
- shared `IPQoS` output formatting used by:
  - `ssh -G` / `sshd -T` output for interactive and bulk QoS values
  - canonical DSCP/legacy token rendering and hex fallback for unknown values
- shared permit-list output formatting used by:
  - `PermitRemoteOpen` in `ssh -G`
  - `PermitOpen` / `PermitListen` in `sshd -T`
  - `any` fallback and joined permit target rendering
- client `TunnelDevice` output formatting used by:
  - `tunneldevice local:remote` lines in `ssh -G`
  - `any` / numeric tunnel endpoint rendering
- client `AddKeysToAgent` output formatting used by:
  - `addkeystoagent confirm <seconds>` lines in `ssh -G`
- client `CanonicalizePermittedCNAMEs` output formatting used by:
  - `canonicalizePermittedcnames source:target ...` lines in `ssh -G`
  - `none` output when the list is empty
- client `ProxyJump` output formatting used by:
  - `proxyjump ...` lines in `ssh -G`
  - bracketed numeric jump-host rendering and preserved extra jump-chain prefixes
- client `RekeyLimit` output formatting used by:
  - `rekeylimit <bytes> <seconds>` lines in `ssh -G`
- client `StreamLocalBindMask` output formatting used by:
  - `streamlocalbindmask 0...` lines in `ssh -G`
  - the shared Rust octal formatter already used by server config output
- client `LogFacility` output formatting used by:
  - `syslogfacility ...` lines in `ssh -G`
  - the shared Rust string formatter already used by server config output
- client `EscapeChar` output formatting used by:
  - `escapechar ...` lines in `ssh -G`
  - `none`, printable characters, and `^X` control rendering
- `a2port()` numeric and service-name port parsing used by:
  - destination and forwarding helpers layered above shared host/port parsing
  - `ssh`, `sshd`, `scp`, `sftp`, and `ssh-keyscan` port consumers
- `parse_pattern_interval()` parsing used by:
  - `ChannelTimeout`
  - similar `pattern=interval` config semantics shared by client/server code
- RSA and ECDSA private-key loading for:
  - legacy PEM
  - PKCS#8
  - encrypted legacy PEM
  - encrypted PKCS#8
- Curve25519/X25519 key exchange helpers
- NIST ECDH key exchange helpers
  (`ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`, `ecdh-sha2-nistp521`)
- classic fixed-group DH key exchange helpers
  (`diffie-hellman-group14-sha1`, `diffie-hellman-group14-sha256`,
  `diffie-hellman-group16-sha512`, `diffie-hellman-group18-sha512`)
- DH-GEX key exchange helpers in Rust mode
  (`diffie-hellman-group-exchange-sha1`,
  `diffie-hellman-group-exchange-sha256`)
- full `mlkem768x25519-sha256` hybrid KEX path
- full `sntrup761x25519-sha512` hybrid KEX path
- AES-CTR transport cipher (`aes128-ctr`, `aes192-ctr`, `aes256-ctr`)
- ChaCha20-Poly1305 transport cipher (`chacha20-poly1305@openssh.com`)
- standalone Rust fuzz targets for:
  - Ed25519 verification
  - NIST ECDH peer/public input handling
  - ChaCha20-Poly1305 packet decrypt/auth failure handling
  - shared config/parser helper ABI coverage including:
    `argv_split`, forwarding spec parsing, `ProxyJump`, hostfile lines,
    user/host targets, permit validation, keyword/multistate lookups,
    option dequoting, `%` / `${}` expansion, domain/env validation,
    absolute-time parsing, and `ChannelTimeout`-style interval parsing

Still on the existing C path today:

- MD5 and SHA1 digest support
- PKCS#11 and security-key code paths
- SK / FIDO private-key deserialization inside decrypted
  `openssh-key-v1` private sections
- most client/server config-file semantics beyond shared tokenization

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
| `rsa` | RSA key generation plus PKCS#1 v1.5 signing and verification for `ssh-rsa`, `rsa-sha2-256`, and `rsa-sha2-512` | <https://github.com/RustCrypto/RSA> | <https://crates.io/crates/rsa> |
| `ed25519-dalek` | Ed25519 key generation, signing, and verification | <https://github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek> | <https://crates.io/crates/ed25519-dalek> |
| `fips203` | ML-KEM-768 encapsulation and decapsulation for the Rust `mlkem768x25519-sha256` hybrid KEX path | <https://github.com/integritychain/fips203> | <https://crates.io/crates/fips203> |
| `sntrup761` | SNTRUP761 encapsulation and decapsulation for the Rust `sntrup761x25519-sha512` hybrid KEX path | <https://github.com/mikelodder7/sntrup761> | <https://crates.io/crates/sntrup761> |
| `x25519-dalek` | X25519 key exchange for `curve25519-sha256*` and the X25519 half of hybrid KEX | <https://github.com/dalek-cryptography/curve25519-dalek/tree/main/x25519-dalek> | <https://crates.io/crates/x25519-dalek> |
| `p256` | NIST P-256 ECDH plus ECDSA support for `ecdh-sha2-nistp256` and `ecdsa-sha2-nistp256` | <https://github.com/RustCrypto/elliptic-curves/tree/master/p256> | <https://crates.io/crates/p256> |
| `p384` | NIST P-384 ECDH plus ECDSA support for `ecdh-sha2-nistp384` and `ecdsa-sha2-nistp384` | <https://github.com/RustCrypto/elliptic-curves/tree/master/p384> | <https://crates.io/crates/p384> |
| `p521` | NIST P-521 ECDH plus ECDSA support for `ecdh-sha2-nistp521` and `ecdsa-sha2-nistp521` | <https://github.com/RustCrypto/elliptic-curves/tree/master/p521> | <https://crates.io/crates/p521> |
| `rand_core` | OS randomness for ephemeral ECDH keys and randomized ECDSA signing where the curve implementation requires it | <https://github.com/rust-random/rand> | <https://crates.io/crates/rand_core> |
| `sha1` | SHA-1 digest with ASN.1 OID support for legacy `ssh-rsa` PKCS#1 v1.5 signatures | <https://github.com/RustCrypto/hashes/tree/master/sha1> | <https://crates.io/crates/sha1> |
| `sha2` | SHA-256 / SHA-512 digest with ASN.1 OID support for `rsa-sha2-256` and `rsa-sha2-512` | <https://github.com/RustCrypto/hashes/tree/master/sha2> | <https://crates.io/crates/sha2> |
| `arbitrary` | Structured fuzz inputs for the Rust fuzz targets | <https://github.com/rust-fuzz/arbitrary> | <https://crates.io/crates/arbitrary> |
| `libfuzzer-sys` | libFuzzer integration for the Rust fuzz targets | <https://github.com/rust-fuzz/libfuzzer> | <https://crates.io/crates/libfuzzer-sys> |

## CI coverage

The `rust-crypto` GitHub Actions job exercises the Rust backend directly.
Today it runs:

- `cargo test --manifest-path rust/crypto/Cargo.toml`
- `cargo build --manifest-path rust/crypto/fuzz/Cargo.toml`
- `cargo run --manifest-path rust/crypto/fuzz/Cargo.toml --bin ed25519_verify -- -runs=1`
- `cargo run --manifest-path rust/crypto/fuzz/Cargo.toml --bin dh_peer -- -runs=1`
- `cargo run --manifest-path rust/crypto/fuzz/Cargo.toml --bin ecdsa_parse -- -runs=1`
- `cargo run --manifest-path rust/crypto/fuzz/Cargo.toml --bin rsa_parse -- -runs=1`
- the OpenSSH `unit` and `t-exec` targets under `--with-rust-crypto`

That gives both Rust-native coverage and OpenSSH integration coverage in CI.

For reproducing `rust-crypto`, `openssl-noec`, and similar CI jobs locally in
Docker, see [CI_REPRO.md](CI_REPRO.md).

The Docker repro image installs current stable Rust via `rustup`, so local
repros do not depend on the distro `cargo` version inside the base image.

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
randomized/property-style checks for digests, Ed25519, RSA, ECDSA, X25519,
NIST ECDH, AES-CTR, and ChaCha20-Poly1305.

The existing OpenSSH unit suite also exercises the Rust config-token parsing
replacements through:

- `regress/unittests/misc/test_argv.c`
- `regress/unittests/misc/test_strdelim.c`
- `regress/unittests/misc/test_hpdelim.c`
- `regress/unittests/misc/test_user_host_port.c`
- `regress/unittests/misc/test_parse.c`
- `regress/unittests/misc/test_convtime.c`
- `regress/unittests/misc/test_misc.c`

That `test_misc` coverage now also includes the Rust-backed `a2port()` path
for numeric and service-name port resolution.

It also includes direct coverage for the Rust-backed `atoi_err()` path and its
error-string mapping used by shared config numeric parsing.

It now also includes direct coverage for the shared Rust-backed
`multistate_lookup()` path used by repeated client/server config enums.

It also includes direct coverage for the shared Rust-backed
`multistate_name()` path used by repeated client/server config formatting.

It also includes direct coverage for the shared Rust-backed `opt_flag()` path
used by boolean option fragments with optional `no-` prefixes.

It also includes direct coverage for the shared Rust-backed env-list lookup
helpers used by `lookup_env_in_list()` and `lookup_setenv_in_list()`.

It also includes direct coverage for the shared Rust-backed `opt_match()`
path used by `name=` style auth-option and `sshsig` field parsing.

It also includes direct coverage for the shared Rust-backed `opt_dequote()`
path used by quoted auth-option and `sshsig` values.

It also includes direct coverage for the shared Rust-backed expansion helpers
via the combined `test_misc` expansion tests.

It also includes direct Rust coverage for the client keyword lookup helper and
`ssh -G` smoke coverage for accepted and rejected client config options.

It also includes `sshd -T` smoke coverage for accepted and rejected
server config options through the Rust-backed keyword lookup path.

It also includes direct Rust coverage for reverse keyword lookup plus
`ssh -G` / `sshd -T` smoke coverage for config output formatting.

It also includes direct Rust coverage for shared config integer formatting plus
`ssh -G` / `sshd -T` smoke coverage for formatted enum and digest-name output.

It also includes direct Rust coverage for client forward output formatting plus
`ssh -G` smoke coverage for dynamic, local, remote, and streamlocal forwards.

It also includes direct Rust coverage for client one-line list formatting plus
`ssh -G` smoke coverage for `CanonicalDomains` and `PermitRemoteOpen`.

It also includes direct Rust coverage for server one-line list formatting plus
`sshd -T` smoke coverage for `AuthorizedKeysFile`, `AuthenticationMethods`,
and `ChannelTimeout`.

The existing OpenSSH `test_convtime` coverage now also exercises the
Rust-backed `convtime()` / `convtime_double()` path.

It also exercises the Rust-backed hostfile parser path through:

- `regress/unittests/hostkeys/test_iterate.c`
- `regress/knownhosts.sh` via the Docker `rust-crypto` repro

For the Rust-backed forwarding parser path, representative local checks are:

```sh
./ssh -G localhost -F /dev/null -L '[host:name]:8080:dest:80' >/dev/null
./ssh -G localhost -F /dev/null -L '[host]x:8080:dest:80'
```

The first should succeed. The second should fail with `Bad local forwarding
specification`.

For the Rust-backed ProxyJump parser path, representative local checks are:

```sh
./ssh -G localhost -F /dev/null -J 'jumpa,ssh://user@jumpb:2200' >/dev/null
./ssh -G localhost -F /dev/null -J 'jumpa,,jumpb'
```

The first should succeed. The second should fail with `Invalid -J argument`.

For the Rust-backed permit validation path, representative local checks are:

```sh
tmpd=$(mktemp -d /tmp/permitcfg.XXXXXX)
printf 'Host *\n    PermitRemoteOpen dest.example:80\n' > "$tmpd/ssh_config"
printf 'PermitOpen dest.example:80\nPermitListen 8080\n' > "$tmpd/sshd_config"
./ssh -G localhost -F "$tmpd/ssh_config" >/dev/null
./sshd -T -f "$tmpd/sshd_config" >/dev/null
```

Those should both succeed. Invalid forms like `PermitRemoteOpen host:0` or
`PermitListen [host]x:22` should fail during config parsing.

For comparative performance measurements between the default/OpenSSL build and
the Rust crypto build, use:

```sh
./contrib/bench-rust-crypto.sh
```

That helper creates throwaway worktrees for both configurations and runs the
existing in-tree unit benchmarks for:

- `regress/unittests/sshkey/test_sshkey`
- `regress/unittests/kex/test_kex`

It also runs higher-level repeated command comparisons for representative user
actions such as:

- `ssh -G ... -F bench/ssh_config`
- `ssh-keygen -l -f key.pub`
- `ssh-keygen -y -f private_key`
- `ssh-keygen -y -P ... -f encrypted_private_key`

It reports benchmark throughput plus wall/user/sys time and max RSS when
available from `/usr/bin/time`. For a broader set including RSA/ECDSA/NIST ECDH
and group14, run:

```sh
./contrib/bench-rust-crypto.sh full
```

For a Linux run on the Caracal builder VM, use:

```sh
./contrib/bench-rust-crypto-remote.sh
```

That wrapper:

- uses `../../caracal-server` when present to provision/start the builder VM,
- ships the current `HEAD` commit to the Linux builder as a git bundle,
- runs the existing `contrib/bench-rust-crypto.sh` there, and
- copies the summary plus logs back to `/tmp/openssh-bench-results/<timestamp>/`.

For the broader benchmark set on the remote Linux host, run:

```sh
./contrib/bench-rust-crypto-remote.sh full
```

Useful overrides:

- `REMOTE_HOST=builder-or-ip` to target a different SSH host
- `START_REMOTE=0` if the Linux machine is already up or is not managed by Caracal
- `STOP_REMOTE=1` to shut the builder VM down after the run
- `KEEP_REMOTE_WORK=1` to leave the remote repo/worktrees/results in place

The remote wrapper benchmarks `HEAD`, matching the local helper's worktree
behavior. Uncommitted local changes are not included. It also assumes the
builder already has the OpenSSH benchmark prerequisites installed
(`autoreconf`, compiler toolchain, `cargo`, `rustc`, etc.); if those are
missing, prime the builder first and rerun the wrapper.

For the Rust-backed fixed-group DH path, representative local checks are:

```sh
./ssh -Q kex | rg 'diffie-hellman-group(14|16|18)'
make -j1 regress/unittests/kex/test_kex
./regress/unittests/kex/test_kex
```

In this Codex environment, real outbound handshake checks for these DH groups
are blocked by local sandbox networking, so `ssh -Q kex` plus `test_kex`
are the practical local validation signals for this slice.

For the Rust-backed DH-GEX path, the most relevant local checks are:

```sh
./ssh -Q kex | rg 'group-exchange'
make -j1 regress/unittests/kex/test_kex
./regress/unittests/kex/test_kex
```

For the full Rust-mode CI-equivalent unit pass in Docker:

```sh
env MAKE_TARGETS=unit ./contrib/ci-repro.sh rust-crypto
```

For the Rust-backed private-key load path, targeted local checks that are
worth rerunning are:

```sh
./ssh-keygen -y -P mekmitasdigoat -f /path/to/rsa_1_pw >/dev/null
./ssh-keygen -y -P mekmitasdigoat -f /path/to/ecdsa_1_pw >/dev/null
./ssh-keygen -y -P wrong -f /path/to/rsa_1_pw >/dev/null
./ssh-keygen -y -P wrong -f /path/to/ecdsa_1_pw >/dev/null
```

The first two should succeed. The second two should fail with the expected
OpenSSH wrong-passphrase message.

For the Rust-backed public text-key path, representative checks are:

```sh
./ssh-keygen -l -f regress/unittests/sshkey/testdata/ed25519_1.pub
./ssh-keygen -l -f regress/unittests/sshkey/testdata/ecdsa_1-cert.pub
./ssh-keygen -l -f regress/unittests/sshkey/testdata/rsa_1.pub
./ssh-keygen -r test -f regress/ed25519_openssh.pub
./ssh-keygen -r test -f regress/rsa_openssh.pub
```

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

To exercise the Rust-backed ECDSA path locally without needing a server that
offers ECDSA host keys:

```sh
printf 'ecdsa rust path\n' > /tmp/rust_ecdsa_msg

./ssh-keygen -q -t ecdsa -b 256 -N '' -f /tmp/rust_ecdsa_256
./ssh-keygen -Y sign -f /tmp/rust_ecdsa_256 -n file /tmp/rust_ecdsa_msg
./ssh-keygen -Y check-novalidate -n file -s /tmp/rust_ecdsa_msg.sig < /tmp/rust_ecdsa_msg

./ssh-keygen -q -t ecdsa -b 384 -N '' -f /tmp/rust_ecdsa_384
./ssh-keygen -Y sign -f /tmp/rust_ecdsa_384 -n file /tmp/rust_ecdsa_msg
./ssh-keygen -Y check-novalidate -n file -s /tmp/rust_ecdsa_msg.sig < /tmp/rust_ecdsa_msg

printf 'ecdsa rust path 521\n' > /tmp/rust_ecdsa_msg_521
./ssh-keygen -q -t ecdsa -b 521 -N '' -f /tmp/rust_ecdsa_521
./ssh-keygen -Y sign -f /tmp/rust_ecdsa_521 -n file /tmp/rust_ecdsa_msg_521
./ssh-keygen -Y check-novalidate -n file -s /tmp/rust_ecdsa_msg_521.sig < /tmp/rust_ecdsa_msg_521
```

To exercise the Rust-backed RSA path locally:

```sh
printf 'rsa rust path\n' > /tmp/rust_rsa_msg
./ssh-keygen -q -t rsa -b 2048 -N '' -f /tmp/rust_rsa_key
./ssh-keygen -Y sign -f /tmp/rust_rsa_key -n file /tmp/rust_rsa_msg
./ssh-keygen -Y check-novalidate -n file -s /tmp/rust_rsa_msg.sig < /tmp/rust_rsa_msg
./ssh -Q key
```

The important lines there are:

- `Good "file" signature with RSA key ...`
- `ssh -Q key` includes `ssh-rsa`

To exercise Rust-backed ECDSA host-key verification against a real server that
offers `ecdsa-sha2-nistp256`:

```sh
./ssh -vv \
  -oBatchMode=yes \
  -oHostKeyAlgorithms=ecdsa-sha2-nistp256 \
  -oPubkeyAcceptedAlgorithms=ssh-ed25519 \
  -i ~/.ssh/id_ed25519 \
  user@host true
```

The important lines there are:

- `kex: host key algorithm: ecdsa-sha2-nistp256`
- `Server host key: ecdsa-sha2-nistp256 ...`
- `Host '...' is known and matches the ECDSA host key.`
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
cargo run --manifest-path rust/crypto/fuzz/Cargo.toml \
  --bin sshkey_metadata -- -runs=1
cargo run --manifest-path rust/crypto/fuzz/Cargo.toml \
  --bin packet_mac -- -runs=1
```

Run a bounded real fuzzing session:

```sh
cd rust/crypto/fuzz
cargo +nightly fuzz run ed25519_verify -- -max_total_time=60
cargo +nightly fuzz run ecdh_peer -- -max_total_time=60
cargo +nightly fuzz run chachapoly_decrypt -- -max_total_time=60
cargo +nightly fuzz run sshkey_metadata -- -max_total_time=60
cargo +nightly fuzz run packet_mac -- -max_total_time=60
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
- `sshkey_metadata`
- `packet_mac`

Notes:

- the CI job only does smoke runs of the configured Rust fuzz targets
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
- Rust-backed PKCS#11 or security-key support,
- full Rust transport cipher coverage,
- feature parity with the default OpenSSL build.
