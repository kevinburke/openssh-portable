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

#define OSSH_RUST_CRYPTO_ABI_VERSION 47U
#define OSSH_RUST_PARSE_STATUS_OK 0
#define OSSH_RUST_PARSE_STATUS_INVALID_FORMAT 1
#define OSSH_RUST_PARSE_STATUS_WRONG_PASSPHRASE 2
#define OSSH_RUST_PARSE_STATUS_EC_CURVE_MISMATCH 3
#define OSSH_RUST_DOMAIN_STATUS_EMPTY 1
#define OSSH_RUST_DOMAIN_STATUS_START_INVALID 2
#define OSSH_RUST_DOMAIN_STATUS_CONSECUTIVE_SEPARATORS 3
#define OSSH_RUST_DOMAIN_STATUS_INVALID_CHARS 4
#define OSSH_RUST_ATOI_STATUS_MISSING 1
#define OSSH_RUST_ATOI_STATUS_INVALID 2
#define OSSH_RUST_ATOI_STATUS_TOO_SMALL 3
#define OSSH_RUST_ATOI_STATUS_TOO_LARGE 4
#define OSSH_RUST_OPT_DEQUOTE_MISSING_START 1
#define OSSH_RUST_OPT_DEQUOTE_MISSING_END 2
#define OSSH_RUST_DOLLAR_EXPAND_INVALID 1
#define OSSH_RUST_FMT_INTARG_MULTISTATE 1
#define OSSH_RUST_FMT_INTARG_YESNO 2
#define OSSH_RUST_FMT_INTARG_DIGEST 3
#define OSSH_RUST_FMT_INTARG_LITERAL_UNSET 1
#define OSSH_RUST_FMT_INTARG_LITERAL_NO 2
#define OSSH_RUST_FMT_INTARG_LITERAL_YES 3
#define OSSH_RUST_FMT_INTARG_LITERAL_UNKNOWN 4
#define OSSH_RUST_FMT_INTARG_LITERAL_MULTISTATE 5
#define OSSH_RUST_FMT_INTARG_LITERAL_MD5 6
#define OSSH_RUST_FMT_INTARG_LITERAL_SHA1 7
#define OSSH_RUST_FMT_INTARG_LITERAL_SHA256 8
#define OSSH_RUST_FMT_INTARG_LITERAL_SHA384 9
#define OSSH_RUST_FMT_INTARG_LITERAL_SHA512 10
#define OSSH_RUST_FORWARD_FMT_LOCAL 1
#define OSSH_RUST_FORWARD_FMT_DYNAMIC 2
#define OSSH_RUST_FORWARD_FMT_REMOTE 3

struct ossh_rust_multistate_entry {
	const char *key;
	int value;
};

struct ossh_rust_keyword_entry {
	const char *key;
	int value;
};
struct ossh_rust_expand_entry {
	const char *key;
	const char *repl;
};
struct ossh_rust_opt_dequote_parse {
	size_t output_len;
	size_t next_offset;
};
struct ossh_rust_dollar_expand_parse {
	size_t output_len;
	uint32_t missing_var;
};
struct ossh_rust_fmt_intarg_parse {
	int literal;
	size_t index;
};
struct ossh_rust_forward_format_parse {
	size_t output_len;
	uint32_t emit;
};
struct ossh_rust_strarray_oneline_parse {
	size_t output_len;
	uint32_t emit;
};
struct ossh_rust_permit_list_line_parse {
	size_t output_len;
	uint32_t emit;
};

struct ossh_rust_strarray_lines_parse {
	size_t output_len;
	uint32_t emit;
};
struct ossh_rust_cfg_string_parse {
	size_t output_len;
	uint32_t emit;
};

struct ossh_rust_cfg_int_parse {
	size_t output_len;
	uint32_t emit;
};

struct ossh_rust_listenaddr_line_parse {
	size_t output_len;
	uint32_t emit;
};
struct ossh_rust_ipqos_line_parse {
	size_t output_len;
	uint32_t emit;
};
struct ossh_rust_tunneldevice_line_parse {
	size_t output_len;
	uint32_t emit;
};
struct ossh_rust_add_keys_to_agent_line_parse {
	size_t output_len;
	uint32_t emit;
};
struct ossh_rust_forwardagent_line_parse {
	size_t output_len;
	uint32_t emit;
};
struct ossh_rust_allowed_cname_entry {
	const char *source_list;
	const char *target_list;
};
struct ossh_rust_canonicalize_permitted_cnames_line_parse {
	size_t output_len;
	uint32_t emit;
};
struct ossh_rust_proxyjump_line_parse {
	size_t output_len;
	uint32_t emit;
};
struct ossh_rust_rekeylimit_line_parse {
	size_t output_len;
	uint32_t emit;
};
struct ossh_rust_controlpersist_line_parse {
	size_t output_len;
	uint32_t emit;
};
struct ossh_rust_connecttimeout_line_parse {
	size_t output_len;
	uint32_t emit;
};
struct ossh_rust_pubkeyauthoptions_line_parse {
	size_t output_len;
	uint32_t emit;
};
struct ossh_rust_permituserenvironment_line_parse {
	size_t output_len;
	uint32_t emit;
};
struct ossh_rust_escapechar_line_parse {
	size_t output_len;
	uint32_t emit;
};
#define OSSH_RUST_STRARRAY_EMPTY_SKIP 0U
#define OSSH_RUST_STRARRAY_EMPTY_NONE 1U
#define OSSH_RUST_STRARRAY_EMPTY_ANY 2U
#define OSSH_RUST_CFG_STRING_EMPTY_SKIP 0U
#define OSSH_RUST_CFG_STRING_EMPTY_NONE 1U
#define OSSH_RUST_CFG_INT_DECIMAL 0U
#define OSSH_RUST_CFG_INT_OCTAL 1U
#define OSSH_RUST_CFG_INT_NONE_ZERO 2U
#define OSSH_RUST_CFG_INT_OBSCURE_KEYS 3U
#define OSSH_RUST_EXPAND_ENABLE_DOLLAR 1U
#define OSSH_RUST_EXPAND_ENABLE_PERCENT 2U
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
struct ossh_rust_sshkey_impl {
	const char *name;
	const char *shortname;
	const char *sigalg;
	int type;
	int nid;
	int cert;
	int sigonly;
	int keybits;
	void *funcs;
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
int ossh_rust_atoi_err(const uint8_t *input, size_t input_len, int *out,
    int *status);
int ossh_rust_multistate_lookup(const uint8_t *input, size_t input_len,
    const struct ossh_rust_multistate_entry *entries, size_t nentries,
    int *out);
int ossh_rust_multistate_name(int value,
    const struct ossh_rust_multistate_entry *entries, size_t nentries,
    size_t *out_index);
int ossh_rust_fmt_intarg(int value, int mode,
    const struct ossh_rust_multistate_entry *entries, size_t nentries,
    struct ossh_rust_fmt_intarg_parse *out);
int ossh_rust_forward_format_parse(int mode,
    const char *listen_host, int listen_port, const char *listen_path,
    const char *connect_host, int connect_port, const char *connect_path,
    struct ossh_rust_forward_format_parse *out);
int ossh_rust_forward_format_write(int mode,
    const char *listen_host, int listen_port, const char *listen_path,
    const char *connect_host, int connect_port, const char *connect_path,
    uint8_t *out, size_t out_len);
int ossh_rust_strarray_oneline_parse(const char * const *vals, size_t nvals,
    uint32_t empty_mode, struct ossh_rust_strarray_oneline_parse *out);
int ossh_rust_strarray_oneline_write(const char * const *vals, size_t nvals,
    uint32_t empty_mode, uint8_t *out, size_t out_len);
int ossh_rust_permit_list_line_parse(const char *prefix,
    const char * const *vals, size_t nvals,
    struct ossh_rust_permit_list_line_parse *out);
int ossh_rust_permit_list_line_write(const char *prefix,
    const char * const *vals, size_t nvals, uint8_t *out, size_t out_len);
int ossh_rust_strarray_lines_parse(const char *prefix,
    const char * const *vals, size_t nvals,
    struct ossh_rust_strarray_lines_parse *out);
int ossh_rust_strarray_lines_write(const char *prefix,
    const char * const *vals, size_t nvals, uint8_t *out, size_t out_len);
int ossh_rust_cfg_string_parse(const char *prefix, const char *value,
    uint32_t empty_mode, struct ossh_rust_cfg_string_parse *out);
int ossh_rust_cfg_string_write(const char *prefix, const char *value,
    uint32_t empty_mode, uint8_t *out, size_t out_len);
int ossh_rust_cfg_int_parse(const char *prefix, int value, uint32_t mode,
    struct ossh_rust_cfg_int_parse *out);
int ossh_rust_cfg_int_write(const char *prefix, int value, uint32_t mode,
    uint8_t *out, size_t out_len);
int ossh_rust_listenaddr_line_parse(const char *addr, const char *port,
    const char *rdomain, uint32_t is_ipv6,
    struct ossh_rust_listenaddr_line_parse *out);
int ossh_rust_listenaddr_line_write(const char *addr, const char *port,
    const char *rdomain, uint32_t is_ipv6, uint8_t *out, size_t out_len);
int ossh_rust_ipqos_line_parse(int interactive, int bulk,
    struct ossh_rust_ipqos_line_parse *out);
int ossh_rust_ipqos_line_write(int interactive, int bulk,
    uint8_t *out, size_t out_len);
int ossh_rust_tunneldevice_line_parse(int local, int remote,
    struct ossh_rust_tunneldevice_line_parse *out);
int ossh_rust_tunneldevice_line_write(int local, int remote,
    uint8_t *out, size_t out_len);
int ossh_rust_add_keys_to_agent_line_parse(int mode, int lifespan,
    struct ossh_rust_add_keys_to_agent_line_parse *out);
int ossh_rust_add_keys_to_agent_line_write(int mode, int lifespan,
    uint8_t *out, size_t out_len);
int ossh_rust_forwardagent_line_parse(int value, const char *socket_path,
    struct ossh_rust_forwardagent_line_parse *out);
int ossh_rust_forwardagent_line_write(int value, const char *socket_path,
    uint8_t *out, size_t out_len);
int ossh_rust_canonicalize_permitted_cnames_line_parse(
    const struct ossh_rust_allowed_cname_entry *entries, size_t nentries,
    struct ossh_rust_canonicalize_permitted_cnames_line_parse *out);
int ossh_rust_canonicalize_permitted_cnames_line_write(
    const struct ossh_rust_allowed_cname_entry *entries, size_t nentries,
    uint8_t *out, size_t out_len);
int ossh_rust_proxyjump_line_parse(const char *extra, const char *user,
    const char *host, int port, struct ossh_rust_proxyjump_line_parse *out);
int ossh_rust_proxyjump_line_write(const char *extra, const char *user,
    const char *host, int port, uint8_t *out, size_t out_len);
int ossh_rust_rekeylimit_line_parse(uint64_t limit, int interval,
    struct ossh_rust_rekeylimit_line_parse *out);
int ossh_rust_rekeylimit_line_write(uint64_t limit, int interval,
    uint8_t *out, size_t out_len);
int ossh_rust_controlpersist_line_parse(int value, int timeout,
    struct ossh_rust_controlpersist_line_parse *out);
int ossh_rust_controlpersist_line_write(int value, int timeout,
    uint8_t *out, size_t out_len);
int ossh_rust_connecttimeout_line_parse(int value,
    struct ossh_rust_connecttimeout_line_parse *out);
int ossh_rust_connecttimeout_line_write(int value,
    uint8_t *out, size_t out_len);
int ossh_rust_pubkeyauthoptions_line_parse(int value,
    struct ossh_rust_pubkeyauthoptions_line_parse *out);
int ossh_rust_pubkeyauthoptions_line_write(int value,
    uint8_t *out, size_t out_len);
int ossh_rust_permituserenvironment_line_parse(int value,
    const char *allowlist,
    struct ossh_rust_permituserenvironment_line_parse *out);
int ossh_rust_permituserenvironment_line_write(int value,
    const char *allowlist, uint8_t *out, size_t out_len);
int ossh_rust_escapechar_line_parse(int value,
    struct ossh_rust_escapechar_line_parse *out);
int ossh_rust_escapechar_line_write(int value, uint8_t *out, size_t out_len);
int ossh_rust_keyword_lookup(const uint8_t *input, size_t input_len,
    const struct ossh_rust_keyword_entry *entries, size_t nentries,
    int ignore_case, int *out);
int ossh_rust_keyword_name(int value,
    const struct ossh_rust_keyword_entry *entries, size_t nentries,
    size_t *out_index);
int ossh_rust_sshkey_type_from_name(const uint8_t *input, size_t input_len,
    const struct ossh_rust_sshkey_impl * const *entries, size_t nentries,
    int allow_short, int *out);
int ossh_rust_sshkey_impl_name_from_type_nid(int type, int nid,
    int want_short, const struct ossh_rust_sshkey_impl * const *entries,
    size_t nentries, const char **out);
int ossh_rust_sshkey_impl_index_from_type(int type,
    const struct ossh_rust_sshkey_impl * const *entries, size_t nentries,
    size_t *out);
int ossh_rust_sshkey_impl_index_from_type_nid(int type, int nid,
    const struct ossh_rust_sshkey_impl * const *entries, size_t nentries,
    size_t *out);
int ossh_rust_sshkey_ecdsa_nid_from_name(const uint8_t *input,
    size_t input_len, const struct ossh_rust_sshkey_impl * const *entries,
    size_t nentries, int *out);
int ossh_rust_sshkey_type_is_valid_ca(int type,
    const struct ossh_rust_sshkey_impl * const *entries, size_t nentries,
    int *out);
int ossh_rust_sshkey_type_is_cert(int type, int *out);
int ossh_rust_sshkey_type_plain(int type, int *out);
int ossh_rust_sshkey_type_certified(int type, int *out);
int ossh_rust_sshkey_type_is_sk(int type, int *out);
int ossh_rust_sshkey_type_can_new(int type,
    const struct ossh_rust_sshkey_impl * const *entries, size_t nentries,
    int *out);
int ossh_rust_sshkey_serialize_plan(int type, int force_plain, int has_cert,
    size_t certblob_len, int *out_type, int *out_use_cert_blob);
int ossh_rust_sshkey_from_private_plan(int type, int nid,
    const struct ossh_rust_sshkey_impl * const *entries, size_t nentries,
    int *out_type, int *out_copy_cert);
int ossh_rust_opt_flag(const uint8_t *opt, size_t opt_len,
    int allow_negate, const uint8_t *input, size_t input_len,
    size_t *out_offset, int *out_result);
int ossh_rust_lookup_env_in_list(const uint8_t *env, size_t env_len,
    const char * const *envs, size_t nenvs, size_t *out_index,
    size_t *out_value_offset);
int ossh_rust_lookup_setenv_in_list(const uint8_t *env, size_t env_len,
    const char * const *envs, size_t nenvs, size_t *out_index,
    size_t *out_value_offset);
int ossh_rust_opt_match(const uint8_t *term, size_t term_len,
    const uint8_t *input, size_t input_len, size_t *out_offset,
    int *out_result);
int ossh_rust_opt_dequote_parse(const uint8_t *input, size_t input_len,
    struct ossh_rust_opt_dequote_parse *out, int *status);
int ossh_rust_opt_dequote_write(const uint8_t *input, size_t input_len,
    uint8_t *out, size_t out_len);
int ossh_rust_dollar_expand_parse(const uint8_t *input, size_t input_len,
    struct ossh_rust_dollar_expand_parse *out, int *status);
int ossh_rust_dollar_expand_write(const uint8_t *input, size_t input_len,
    uint8_t *out, size_t out_len);
int ossh_rust_expand_parse(const uint8_t *input, size_t input_len,
    uint32_t flags, const struct ossh_rust_expand_entry *entries,
    size_t nentries, struct ossh_rust_dollar_expand_parse *out, int *status);
int ossh_rust_expand_write(const uint8_t *input, size_t input_len,
    uint32_t flags, const struct ossh_rust_expand_entry *entries,
    size_t nentries, uint8_t *out, size_t out_len);
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
void *ossh_rust_hmac_start(int alg);
int ossh_rust_hmac_init(void *ctx, const uint8_t *key, size_t key_len);
int ossh_rust_hmac_update(void *ctx, const uint8_t *data, size_t data_len);
int ossh_rust_hmac_final(void *ctx, uint8_t *out, size_t out_len);
void ossh_rust_hmac_free(void *ctx);
void *ossh_rust_mac_start(int alg, int truncate_bits);
int ossh_rust_mac_init(void *ctx, const uint8_t *key, size_t key_len);
int ossh_rust_mac_compute(void *ctx, uint32_t seqno, const uint8_t *data,
    size_t data_len, uint8_t *out, size_t out_len);
int ossh_rust_mac_check(void *ctx, uint32_t seqno, const uint8_t *data,
    size_t data_len, const uint8_t *their_mac, size_t their_mac_len);
void ossh_rust_mac_free(void *ctx);
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
