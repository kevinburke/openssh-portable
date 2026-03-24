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

#define OSSH_RUST_CRYPTO_ABI_VERSION 8U
#define OSSH_RUST_ECDH_NISTP256 1
#define OSSH_RUST_ECDH_NISTP384 2
#define OSSH_RUST_ECDH_NISTP521 3
#define OSSH_RUST_RSA_COMPONENT_N 1
#define OSSH_RUST_RSA_COMPONENT_E 2
#define OSSH_RUST_RSA_COMPONENT_D 3
#define OSSH_RUST_RSA_COMPONENT_IQMP 4
#define OSSH_RUST_RSA_COMPONENT_P 5
#define OSSH_RUST_RSA_COMPONENT_Q 6
#ifndef NID_X9_62_prime256v1
#define NID_X9_62_prime256v1 415
#endif
#ifndef NID_secp384r1
#define NID_secp384r1 715
#endif
#ifndef NID_secp521r1
#define NID_secp521r1 716
#endif

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
int ossh_rust_ecdh_keypair(int curve_id, uint8_t *secret_key,
    size_t secret_key_len, uint8_t *public_key, size_t public_key_len);
int ossh_rust_ecdh_shared_secret(int curve_id, const uint8_t *secret_key,
    size_t secret_key_len, const uint8_t *public_key, size_t public_key_len,
    uint8_t *shared_secret, size_t shared_secret_len);
void *ossh_rust_ecdsa_generate(int curve_nid);
void *ossh_rust_ecdsa_from_public(int curve_nid, const uint8_t *public_key,
    size_t public_key_len);
void *ossh_rust_ecdsa_from_private(int curve_nid, const uint8_t *public_key,
    size_t public_key_len, const uint8_t *private_key, size_t private_key_len);
void *ossh_rust_ecdsa_copy_public(const void *key);
int ossh_rust_ecdsa_equal_public(const void *a, const void *b);
int ossh_rust_ecdsa_export_public(const void *key, uint8_t *public_key,
    size_t public_key_len);
int ossh_rust_ecdsa_export_private(const void *key, uint8_t *private_key,
    size_t private_key_len);
int ossh_rust_ecdsa_sign_prehashed(const void *key, const uint8_t *digest,
    size_t digest_len, uint8_t *signature, size_t signature_len);
int ossh_rust_ecdsa_verify_prehashed(const void *key, const uint8_t *digest,
    size_t digest_len, const uint8_t *signature, size_t signature_len);
void ossh_rust_ecdsa_free(void *key);
void *ossh_rust_rsa_generate(size_t bits);
void *ossh_rust_rsa_from_public(const uint8_t *modulus, size_t modulus_len,
    const uint8_t *exponent, size_t exponent_len);
void *ossh_rust_rsa_from_private(const uint8_t *modulus, size_t modulus_len,
    const uint8_t *exponent, size_t exponent_len,
    const uint8_t *private_exponent, size_t private_exponent_len,
    const uint8_t *iqmp, size_t iqmp_len, const uint8_t *prime_p,
    size_t prime_p_len, const uint8_t *prime_q, size_t prime_q_len);
void *ossh_rust_rsa_copy_public(const void *key);
int ossh_rust_rsa_equal_public(const void *a, const void *b);
size_t ossh_rust_rsa_bits(const void *key);
size_t ossh_rust_rsa_component_len(const void *key, int component);
int ossh_rust_rsa_export_component(const void *key, int component,
    uint8_t *out, size_t out_len);
int ossh_rust_rsa_sign_prehashed(const void *key, int hash_alg,
    const uint8_t *digest, size_t digest_len, uint8_t *signature,
    size_t signature_len);
int ossh_rust_rsa_verify_prehashed(const void *key, int hash_alg,
    const uint8_t *digest, size_t digest_len, const uint8_t *signature,
    size_t signature_len);
void ossh_rust_rsa_free(void *key);
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
