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

#define OSSH_RUST_CRYPTO_ABI_VERSION 5U

uint32_t ossh_rust_crypto_abi_version(void);
const char *ossh_rust_crypto_backend_label(void);
void *ossh_rust_digest_start(int alg);
void *ossh_rust_digest_copy(const void *ctx);
int ossh_rust_digest_update(void *ctx, const uint8_t *data, size_t len);
int ossh_rust_digest_final(const void *ctx, uint8_t *out, size_t out_len);
void ossh_rust_digest_free(void *ctx);
int ossh_rust_ed25519_public_from_seed(const uint8_t *seed, size_t seed_len,
    uint8_t *public_key, size_t public_key_len);
int ossh_rust_ed25519_sign(uint8_t *sig, size_t sig_len, const uint8_t *msg,
    size_t msg_len, const uint8_t *secret_key, size_t secret_key_len);
int ossh_rust_ed25519_verify(const uint8_t *sig, size_t sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *public_key,
    size_t public_key_len);
int ossh_rust_curve25519_public_from_secret(uint8_t *public_key,
    size_t public_key_len, const uint8_t *secret_key, size_t secret_key_len);
int ossh_rust_curve25519_shared_secret(uint8_t *shared_secret,
    size_t shared_secret_len, const uint8_t *secret_key, size_t secret_key_len,
    const uint8_t *public_key, size_t public_key_len);
void *ossh_rust_aesctr_init(const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len);
int ossh_rust_aesctr_set_iv(void *ctx, const uint8_t *iv, size_t iv_len);
int ossh_rust_aesctr_get_iv(const void *ctx, uint8_t *iv, size_t iv_len);
int ossh_rust_aesctr_crypt(void *ctx, const uint8_t *src, uint8_t *dst,
    size_t len);
void ossh_rust_aesctr_free(void *ctx);
void *ossh_rust_chachapoly_new(const uint8_t *key, size_t key_len);
int ossh_rust_chachapoly_crypt(void *ctx, uint32_t seqnr, uint8_t *dest,
    size_t dest_len, const uint8_t *src, size_t src_len, uint32_t len,
    uint32_t aadlen, uint32_t authlen, int do_encrypt);
int ossh_rust_chachapoly_get_length(void *ctx, uint32_t *plenp,
    uint32_t seqnr, const uint8_t *cp, size_t len);
void ossh_rust_chachapoly_free(void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* RUST_CRYPTO_H */
