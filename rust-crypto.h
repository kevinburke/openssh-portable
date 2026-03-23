/*
 * Rust crypto backend ABI bootstrap.
 *
 * Phase 0 keeps the ABI deliberately small so the build can prove out the
 * Rust toolchain integration before transport crypto is routed through it.
 */

#ifndef RUST_CRYPTO_H
#define RUST_CRYPTO_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OSSH_RUST_CRYPTO_ABI_VERSION 1U

uint32_t ossh_rust_crypto_abi_version(void);
const char *ossh_rust_crypto_backend_label(void);

#ifdef __cplusplus
}
#endif

#endif /* RUST_CRYPTO_H */
