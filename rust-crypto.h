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

#define OSSH_RUST_CRYPTO_ABI_VERSION 33U
#define OSSH_RUST_PARSE_STATUS_OK 0
#define OSSH_RUST_PARSE_STATUS_INVALID_FORMAT 1
#define OSSH_RUST_PARSE_STATUS_WRONG_PASSPHRASE 2
#define OSSH_RUST_PARSE_STATUS_EC_CURVE_MISMATCH 3
#define OSSH_RUST_DOMAIN_STATUS_EMPTY 1
#define OSSH_RUST_DOMAIN_STATUS_START_INVALID 2
#define OSSH_RUST_DOMAIN_STATUS_CONSECUTIVE_SEPARATORS 3
#define OSSH_RUST_DOMAIN_STATUS_INVALID_CHARS 4
#define OSSH_RUST_PRIVATE2_KDF_NONE 0
#define OSSH_RUST_PRIVATE2_KDF_BCRYPT 1
#define OSSH_RUST_PRIVATE2_KEY_UNSUPPORTED 0
#define OSSH_RUST_PRIVATE2_KEY_ED25519 1
#define OSSH_RUST_PRIVATE2_KEY_ECDSA 2
#define OSSH_RUST_PRIVATE2_KEY_RSA 3
#define OSSH_RUST_DH_GROUP14 14
#define OSSH_RUST_DH_GROUP16 16
#define OSSH_RUST_DH_GROUP18 18
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
struct ossh_rust_cert_body_parse {
	uint64_t serial;
	uint32_t cert_type;
	uint64_t valid_after;
	uint64_t valid_before;
	size_t signed_consumed;
	size_t total_consumed;
	size_t key_id_offset;
	size_t key_id_len;
	size_t principals_offset;
	size_t principals_len;
	size_t critical_offset;
	size_t critical_len;
	size_t extensions_offset;
	size_t extensions_len;
	size_t ca_key_offset;
	size_t ca_key_len;
	size_t signature_offset;
	size_t signature_len;
};
struct ossh_rust_private2_header_parse {
	size_t ciphername_offset;
	size_t ciphername_len;
	size_t kdfname_offset;
	size_t kdfname_len;
	size_t kdf_offset;
	size_t kdf_len;
	size_t public_key_offset;
	size_t public_key_len;
	size_t encrypted_offset;
	size_t encrypted_len;
	size_t bcrypt_salt_offset;
	size_t bcrypt_salt_len;
	uint32_t bcrypt_rounds;
	uint32_t kdf_kind;
};
struct ossh_rust_private2_plaintext_parse {
	uint32_t key_kind;
	int curve_nid;
	uint32_t is_cert;
	size_t cert_offset;
	size_t cert_len;
	size_t comment_offset;
	size_t comment_len;
	size_t part1_offset;
	size_t part1_len;
	size_t part2_offset;
	size_t part2_len;
	size_t part3_offset;
	size_t part3_len;
	size_t part4_offset;
	size_t part4_len;
	size_t part5_offset;
	size_t part5_len;
	size_t part6_offset;
	size_t part6_len;
};
struct ossh_rust_public_line_parse {
	size_t key_type_offset;
	size_t key_type_len;
	size_t key_blob_offset;
	size_t key_blob_len;
	size_t comment_offset;
};
struct ossh_rust_argv_split_parse {
	size_t argc;
	size_t packed_len;
};
struct ossh_rust_strdelim_parse {
	size_t next_offset;
	uint32_t next_is_null;
};
struct ossh_rust_hpdelim_parse {
	size_t next_offset;
	uint32_t next_is_null;
	uint8_t delim;
};
struct ossh_rust_forward_field_parse {
	size_t arg_offset;
	size_t next_offset;
	uint32_t ispath;
};
struct ossh_rust_forward_parse {
	uint32_t field_count;
	size_t listen_host_offset;
	size_t listen_host_len;
	size_t listen_port_offset;
	size_t listen_port_len;
	size_t listen_path_offset;
	size_t listen_path_len;
	size_t connect_host_offset;
	size_t connect_host_len;
	size_t connect_port_offset;
	size_t connect_port_len;
	size_t connect_path_offset;
	size_t connect_path_len;
	uint32_t has_listen_host;
	uint32_t has_listen_port;
	uint32_t has_listen_path;
	uint32_t has_connect_host;
	uint32_t has_connect_host_socks;
	uint32_t has_connect_port;
	uint32_t has_connect_path;
	int32_t listen_port_value;
	int32_t connect_port_value;
};
struct ossh_rust_jump_parse {
	size_t first_offset;
	size_t first_len;
	size_t extra_len;
	uint32_t is_none;
	uint32_t first_is_uri;
	uint32_t has_extra;
};
struct ossh_rust_hostfile_line_parse {
	uint32_t kind;
	uint32_t marker;
	size_t hosts_offset;
	size_t hosts_len;
	size_t rawkey_offset;
	size_t keytype_offset;
	size_t keytype_len;
};
#define OSSH_RUST_HOSTFILE_LINE_COMMENT 1
#define OSSH_RUST_HOSTFILE_LINE_ENTRY 2
#define OSSH_RUST_HOSTFILE_LINE_INVALID_MARKER 3
#define OSSH_RUST_HOSTFILE_LINE_INVALID_ENTRY 4
struct ossh_rust_user_host_port_parse {
	size_t user_offset;
	size_t user_len;
	size_t host_offset;
	size_t host_len;
	size_t port_offset;
	size_t port_len;
	uint32_t has_user;
	uint32_t has_port;
};
struct ossh_rust_uri_parse {
	size_t user_offset;
	size_t user_len;
	size_t host_offset;
	size_t host_len;
	size_t port_offset;
	size_t port_len;
	size_t path_offset;
	size_t path_len;
	uint32_t has_user;
	uint32_t has_port;
	uint32_t has_path;
};
struct ossh_rust_user_host_path_parse {
	size_t user_offset;
	size_t user_len;
	size_t host_offset;
	size_t host_len;
	size_t path_offset;
	size_t path_len;
	uint32_t has_user;
};
struct ossh_rust_pattern_interval_parse {
	size_t type_len;
	size_t interval_offset;
	size_t interval_len;
};
int ossh_rust_cert_parse_body(const uint8_t *input, size_t input_len,
    struct ossh_rust_cert_body_parse *out);
size_t ossh_rust_private2_decode_len(const uint8_t *input, size_t input_len);
int ossh_rust_private2_decode_write(const uint8_t *input, size_t input_len,
    uint8_t *out, size_t out_len);
int ossh_rust_private2_parse_header(const uint8_t *decoded, size_t decoded_len,
    struct ossh_rust_private2_header_parse *out);
int ossh_rust_private2_parse_plaintext(const uint8_t *decrypted,
    size_t decrypted_len, struct ossh_rust_private2_plaintext_parse *out);
int ossh_rust_public_line_parse(const uint8_t *input, size_t input_len,
    struct ossh_rust_public_line_parse *out);
size_t ossh_rust_public_blob_decode_len(const uint8_t *input, size_t input_len);
int ossh_rust_public_blob_decode_write(const uint8_t *input, size_t input_len,
    uint8_t *out, size_t out_len);
int ossh_rust_argv_split_parse(const uint8_t *input, size_t input_len,
    int terminate_on_comment, struct ossh_rust_argv_split_parse *out);
int ossh_rust_argv_split_write(const uint8_t *input, size_t input_len,
    int terminate_on_comment, uint8_t *out, size_t out_len);
int ossh_rust_strdelim_parse(uint8_t *input, size_t input_len,
    int split_equals, struct ossh_rust_strdelim_parse *out);
int ossh_rust_hpdelim2_parse(uint8_t *input, size_t input_len,
    struct ossh_rust_hpdelim_parse *out);
int ossh_rust_parse_forward_field(uint8_t *input, size_t input_len,
    struct ossh_rust_forward_field_parse *out);
int ossh_rust_parse_forward(uint8_t *input, size_t input_len, int dynamicfwd,
    int remotefwd, struct ossh_rust_forward_parse *out);
int ossh_rust_parse_jump(const uint8_t *input, size_t input_len,
    struct ossh_rust_jump_parse *out);
int ossh_rust_parse_hostfile_line(const uint8_t *input, size_t input_len,
    struct ossh_rust_hostfile_line_parse *out);
int ossh_rust_host_hash(const uint8_t *host, size_t host_len,
    const uint8_t *name_from_hostfile, size_t src_len, uint8_t *out,
    size_t out_len);
int ossh_rust_match_hashed_host(const uint8_t *host, size_t host_len,
    const uint8_t *names, size_t names_len);
int ossh_rust_parse_user_host_port(const uint8_t *input, size_t input_len,
    struct ossh_rust_user_host_port_parse *out);
int ossh_rust_parse_uri(const uint8_t *input, size_t input_len,
    struct ossh_rust_uri_parse *out);
int ossh_rust_parse_user_host_path(const uint8_t *input, size_t input_len,
    struct ossh_rust_user_host_path_parse *out);
int ossh_rust_validate_permit(const uint8_t *input, size_t input_len,
    int allow_bare_port);
int ossh_rust_parse_ipqos(const uint8_t *input, size_t input_len, int *out);
int ossh_rust_a2port(const uint8_t *input, size_t input_len, int *out);
int ossh_rust_valid_env_name(const uint8_t *input, size_t input_len);
int ossh_rust_valid_domain(uint8_t *input, size_t input_len, int makelower,
    int *status);
int ossh_rust_parse_absolute_time(const uint8_t *input, size_t input_len,
    uint64_t *tp);
int ossh_rust_convtime_double(const uint8_t *input, size_t input_len,
    double *out);
int ossh_rust_parse_pattern_interval(const uint8_t *input, size_t input_len,
    struct ossh_rust_pattern_interval_parse *out);
void *ossh_rust_dh_group_new(int group_id);
void *ossh_rust_dh_group_from_params(const uint8_t *generator,
    size_t generator_len, const uint8_t *modulus, size_t modulus_len);
int ossh_rust_dh_generate_key(void *group, size_t need_bits);
size_t ossh_rust_dh_public_len(const void *group);
int ossh_rust_dh_export_public(const void *group, uint8_t *out, size_t out_len);
size_t ossh_rust_dh_modulus_len(const void *group);
int ossh_rust_dh_export_modulus(const void *group, uint8_t *out,
    size_t out_len);
size_t ossh_rust_dh_generator_len(const void *group);
int ossh_rust_dh_export_generator(const void *group, uint8_t *out,
    size_t out_len);
int ossh_rust_dh_shared_secret(const void *group, const uint8_t *peer_public,
    size_t peer_public_len, uint8_t *out, size_t out_len);
void ossh_rust_dh_free(void *group);
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
int ossh_rust_ed25519_parse_public_blob(const uint8_t *blob, size_t blob_len,
    uint8_t *public_key, size_t public_key_len, size_t *consumed_len);
int ossh_rust_curve25519_public_from_secret(uint8_t *public_key,
    size_t public_key_len, const uint8_t *secret_key, size_t secret_key_len);
int ossh_rust_curve25519_shared_secret(uint8_t *shared_secret,
    size_t shared_secret_len, const uint8_t *secret_key, size_t secret_key_len,
    const uint8_t *public_key, size_t public_key_len);
int ossh_rust_mlkem768x25519_keypair(uint8_t *client_blob,
    size_t client_blob_len, uint8_t *mlkem_secret, size_t mlkem_secret_len,
    uint8_t *curve25519_secret, size_t curve25519_secret_len);
int ossh_rust_mlkem768x25519_enc(const uint8_t *client_blob,
    size_t client_blob_len, uint8_t *server_blob, size_t server_blob_len,
    uint8_t *shared_hash, size_t shared_hash_len);
int ossh_rust_mlkem768x25519_dec(const uint8_t *server_blob,
    size_t server_blob_len, const uint8_t *mlkem_secret,
    size_t mlkem_secret_len, const uint8_t *curve25519_secret,
    size_t curve25519_secret_len, uint8_t *shared_hash,
    size_t shared_hash_len);
int ossh_rust_sntrup761x25519_keypair(uint8_t *client_blob,
    size_t client_blob_len, uint8_t *sntrup_secret, size_t sntrup_secret_len,
    uint8_t *curve25519_secret, size_t curve25519_secret_len);
int ossh_rust_sntrup761x25519_enc(const uint8_t *client_blob,
    size_t client_blob_len, uint8_t *server_blob, size_t server_blob_len,
    uint8_t *shared_hash, size_t shared_hash_len);
int ossh_rust_sntrup761x25519_dec(const uint8_t *server_blob,
    size_t server_blob_len, const uint8_t *sntrup_secret,
    size_t sntrup_secret_len, const uint8_t *curve25519_secret,
    size_t curve25519_secret_len, uint8_t *shared_hash,
    size_t shared_hash_len);
int ossh_rust_ecdh_keypair(int curve_id, uint8_t *secret_key,
    size_t secret_key_len, uint8_t *public_key, size_t public_key_len);
int ossh_rust_ecdh_shared_secret(int curve_id, const uint8_t *secret_key,
    size_t secret_key_len, const uint8_t *public_key, size_t public_key_len,
    uint8_t *shared_secret, size_t shared_secret_len);
void *ossh_rust_ecdsa_generate(int curve_nid);
void *ossh_rust_ecdsa_parse_public_blob(int curve_nid, const uint8_t *blob,
    size_t blob_len, size_t *consumed_len, int *parse_status);
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
int ossh_rust_ecdsa_curve_nid(const void *key);
void *ossh_rust_ecdsa_parse_private_pem(const uint8_t *blob, size_t blob_len);
void *ossh_rust_ecdsa_parse_private_pem_passphrase(const uint8_t *blob,
    size_t blob_len, const uint8_t *passphrase, size_t passphrase_len,
    int *status);
size_t ossh_rust_ecdsa_private_pem_len(const void *key, int format);
int ossh_rust_ecdsa_private_pem_write(const void *key, int format,
    uint8_t *out, size_t out_len);
int ossh_rust_ecdsa_sign_prehashed(const void *key, const uint8_t *digest,
    size_t digest_len, uint8_t *signature, size_t signature_len);
int ossh_rust_ecdsa_verify_prehashed(const void *key, const uint8_t *digest,
    size_t digest_len, const uint8_t *signature, size_t signature_len);
void ossh_rust_ecdsa_free(void *key);
void *ossh_rust_rsa_generate(size_t bits);
void *ossh_rust_rsa_parse_public_blob(const uint8_t *blob, size_t blob_len,
    size_t *consumed_len);
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
void *ossh_rust_rsa_parse_private_pem(const uint8_t *blob, size_t blob_len);
void *ossh_rust_rsa_parse_private_pem_passphrase(const uint8_t *blob,
    size_t blob_len, const uint8_t *passphrase, size_t passphrase_len,
    int *status);
size_t ossh_rust_rsa_private_pem_len(const void *key, int format);
int ossh_rust_rsa_private_pem_write(const void *key, int format, uint8_t *out,
    size_t out_len);
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
