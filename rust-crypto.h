/*
 * Rust crypto backend ABI.
 *
 * Phase 1 keeps the ABI narrow and explicit: the C side retains the existing
 * OpenSSH crypto APIs while Rust owns specific algorithm implementations.
 */

#ifndef RUST_CRYPTO_H
#define RUST_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OSSH_RUST_CRYPTO_ABI_VERSION 2U

uint32_t ossh_rust_crypto_abi_version(void);
const char *ossh_rust_crypto_backend_label(void);
void *ossh_rust_digest_start(int alg);
void *ossh_rust_digest_copy(const void *ctx);
int ossh_rust_digest_update(void *ctx, const uint8_t *data, size_t len);
int ossh_rust_digest_final(const void *ctx, uint8_t *out, size_t out_len);
void ossh_rust_digest_free(void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* RUST_CRYPTO_H */
