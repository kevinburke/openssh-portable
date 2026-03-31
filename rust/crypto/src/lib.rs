mod cert;
mod cipher;
mod dh;
mod digest;
mod ecdsa;
mod hmac;
mod kex;
mod mac;
mod openssh_key;
mod private_pem;
mod rsa;
mod sshkey_meta;
mod util;

use core::ffi::{c_char, c_double, c_int, c_void};
use core::slice;

use cert::parse_cert_body;
use cipher::{
    aesctr_crypt, aesctr_free, aesctr_get_iv, aesctr_init, aesctr_set_iv,
    chachapoly_crypt, chachapoly_free, chachapoly_get_length, chachapoly_new,
};
use dh::{
    dh_export_generator, dh_export_modulus, dh_export_public, dh_free, dh_generate_key,
    dh_generator_len, dh_group_from_params, dh_group_new, dh_modulus_len, dh_public_len,
    dh_shared_secret,
};
use digest::DigestState;
use ecdsa::{
    ecdsa_copy_public, ecdsa_equal_public, ecdsa_export_private, ecdsa_export_public,
    ecdsa_free, ecdsa_from_private, ecdsa_from_public, ecdsa_generate, ecdsa_curve_nid,
    ecdsa_parse_private_pem, ecdsa_parse_private_pem_with_passphrase, ecdsa_parse_public_blob,
    ecdsa_private_pem_len, ecdsa_private_pem_write, ecdsa_sign_prehashed,
    ecdsa_verify_prehashed, OSSH_RUST_ECDSA_PARSE_CURVE_MISMATCH,
    OSSH_RUST_ECDSA_PARSE_INVALID_FORMAT, OSSH_RUST_ECDSA_PARSE_OK,
};
use hmac::HmacState;
use kex::{
    curve25519_public_from_secret, curve25519_shared_secret, ed25519_parse_public_blob,
    ed25519_public_from_seed, ed25519_sign, ed25519_verify, mlkem768x25519_dec,
    mlkem768x25519_enc, mlkem768x25519_keypair, sntrup761x25519_dec,
    sntrup761x25519_enc, sntrup761x25519_keypair, EcdhCurve,
};
use mac::PacketMacState;
use openssh_key::{
    openssh_private2_decode_len, openssh_private2_decode_write, openssh_private2_parse,
    openssh_private2_parse_plaintext, openssh_public_blob_decode_len,
    openssh_public_blob_decode_write, openssh_public_line_parse,
};
use private_pem::PrivatePemError;
use rsa::{
    rsa_bits, rsa_component_len, rsa_copy_public, rsa_equal_public, rsa_export_component, rsa_free,
    rsa_from_private, rsa_from_public, rsa_generate, rsa_parse_private_pem,
    rsa_parse_private_pem_with_passphrase, rsa_parse_public_blob,
    rsa_private_pem_len, rsa_private_pem_write, rsa_sign_prehashed, rsa_verify_prehashed,
};
use sshkey_meta::{
    sshkey_equal_plan as rust_sshkey_equal_plan,
    sshkey_ecdsa_nid_from_name as rust_sshkey_ecdsa_nid_from_name,
    sshkey_equal_public_plan as rust_sshkey_equal_public_plan,
    sshkey_from_blob_plan as rust_sshkey_from_blob_plan,
    sshkey_free_contents_plan as rust_sshkey_free_contents_plan,
    sshkey_from_private_plan as rust_sshkey_from_private_plan,
    sshkey_generate_plan as rust_sshkey_generate_plan,
    sshkey_impl_index_from_type as rust_sshkey_impl_index_from_type,
    sshkey_impl_index_from_type_nid as rust_sshkey_impl_index_from_type_nid,
    sshkey_impl_name_from_type_nid as rust_sshkey_impl_name_from_type_nid,
    sshkey_serialize_plan as rust_sshkey_serialize_plan,
    sshkey_type_can_new as rust_sshkey_type_can_new,
    sshkey_type_certified as rust_sshkey_type_certified,
    sshkey_type_from_name as rust_sshkey_type_from_name,
    sshkey_type_is_cert as rust_sshkey_type_is_cert,
    sshkey_type_is_sk as rust_sshkey_type_is_sk,
    sshkey_type_is_valid_ca as rust_sshkey_type_is_valid_ca, RustSshkeyImpl,
    sshkey_type_plain as rust_sshkey_type_plain,
};
use util::{
    a2port, add_keys_to_agent_line_parse, add_keys_to_agent_line_write,
    argv_split_parse, argv_split_write, host_hash_write, match_hashed_host,
    atoi_err, cfg_int_parse, cfg_int_write, cfg_string_parse, cfg_string_write, dollar_expand_parse,
    dollar_expand_write, expand_parse, expand_write, ipqos_line_parse, ipqos_line_write,
    listenaddr_line_parse, listenaddr_line_write,
    connecttimeout_line_parse, connecttimeout_line_write,
    controlpersist_line_parse, controlpersist_line_write,
    forwardagent_line_parse, forwardagent_line_write,
    fmt_intarg_parse, forward_format_parse, forward_format_write,
    keyword_lookup, keyword_name,
    permituserenvironment_line_parse, permituserenvironment_line_write,
    permit_list_line_parse, permit_list_line_write,
    pubkeyauthoptions_line_parse, pubkeyauthoptions_line_write,
    proxyjump_line_parse, proxyjump_line_write,
    escapechar_line_parse, escapechar_line_write,
    rekeylimit_line_parse, rekeylimit_line_write,
    tunneldevice_line_parse, tunneldevice_line_write,
    canonicalize_permitted_cnames_line_parse,
    canonicalize_permitted_cnames_line_write,
    lookup_env_in_list_parse, lookup_setenv_in_list_parse, multistate_lookup,
    multistate_name, opt_dequote_parse, opt_dequote_write, opt_flag_parse,
    opt_match_parse, parse_convtime_double, parse_forward_field_in_place, parse_forward_in_place,
    parse_hostfile_line, parse_ipqos, parse_jump, parse_pattern_interval, read_slice,
    strarray_lines_parse, strarray_lines_write, strarray_oneline_parse,
    strarray_oneline_write, strdelim_parse_in_place,
    valid_domain, valid_env_name, validate_permit, write_prefix, ATOI_STATUS_INVALID,
    ATOI_STATUS_MISSING, ATOI_STATUS_TOO_LARGE, ATOI_STATUS_TOO_SMALL,
    AllowedCnameEntry, DOMAIN_STATUS_CONSECUTIVE_SEPARATORS, DOMAIN_STATUS_EMPTY,
    DOMAIN_STATUS_INVALID_CHARS, DOMAIN_STATUS_START_INVALID, DOLLAR_EXPAND_INVALID,
    ExpandEntry, KeywordEntry, MultistateEntry, OPT_DEQUOTE_MISSING_END,
    OPT_DEQUOTE_MISSING_START,
};

const OSSH_RUST_CRYPTO_ABI_VERSION: u32 = 48;
const OSSH_RUST_PARSE_STATUS_OK: c_int = 0;
const OSSH_RUST_PARSE_STATUS_INVALID_FORMAT: c_int = 1;
const OSSH_RUST_PARSE_STATUS_WRONG_PASSPHRASE: c_int = 2;
const OSSH_RUST_PARSE_STATUS_EC_CURVE_MISMATCH: c_int = 3;
const OSSH_RUST_DOMAIN_STATUS_EMPTY: c_int = DOMAIN_STATUS_EMPTY;
const OSSH_RUST_DOMAIN_STATUS_START_INVALID: c_int = DOMAIN_STATUS_START_INVALID;
const OSSH_RUST_DOMAIN_STATUS_CONSECUTIVE_SEPARATORS: c_int =
    DOMAIN_STATUS_CONSECUTIVE_SEPARATORS;
const OSSH_RUST_DOMAIN_STATUS_INVALID_CHARS: c_int = DOMAIN_STATUS_INVALID_CHARS;
const OSSH_RUST_ATOI_STATUS_MISSING: c_int = ATOI_STATUS_MISSING;
const OSSH_RUST_ATOI_STATUS_INVALID: c_int = ATOI_STATUS_INVALID;
const OSSH_RUST_ATOI_STATUS_TOO_SMALL: c_int = ATOI_STATUS_TOO_SMALL;
const OSSH_RUST_ATOI_STATUS_TOO_LARGE: c_int = ATOI_STATUS_TOO_LARGE;
const OSSH_RUST_OPT_DEQUOTE_MISSING_START: c_int = OPT_DEQUOTE_MISSING_START;
const OSSH_RUST_OPT_DEQUOTE_MISSING_END: c_int = OPT_DEQUOTE_MISSING_END;
const OSSH_RUST_DOLLAR_EXPAND_INVALID: c_int = DOLLAR_EXPAND_INVALID;
static BACKEND_LABEL: &[u8] = b"Rust crypto backend\0";

fn store_parse_status(status: *mut c_int, value: c_int) {
    if !status.is_null() {
        unsafe {
            *status = value;
        }
    }
}

fn parse_status(err: PrivatePemError) -> c_int {
    match err {
        PrivatePemError::InvalidFormat => OSSH_RUST_PARSE_STATUS_INVALID_FORMAT,
        PrivatePemError::WrongPassphrase => OSSH_RUST_PARSE_STATUS_WRONG_PASSPHRASE,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_crypto_abi_version() -> u32 {
    OSSH_RUST_CRYPTO_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_crypto_backend_label() -> *const c_char {
    BACKEND_LABEL.as_ptr().cast()
}

#[repr(C)]
pub struct RustCertBodyParse {
    serial: u64,
    cert_type: u32,
    valid_after: u64,
    valid_before: u64,
    signed_consumed: usize,
    total_consumed: usize,
    key_id_offset: usize,
    key_id_len: usize,
    principals_offset: usize,
    principals_len: usize,
    critical_offset: usize,
    critical_len: usize,
    extensions_offset: usize,
    extensions_len: usize,
    ca_key_offset: usize,
    ca_key_len: usize,
    signature_offset: usize,
    signature_len: usize,
}

pub type RustMultistateEntry = MultistateEntry;
pub type RustKeywordEntry = KeywordEntry;
pub type RustExpandEntry = ExpandEntry;
pub type RustSshkeyImplEntry = RustSshkeyImpl;

#[repr(C)]
pub struct RustPrivate2HeaderParse {
    ciphername_offset: usize,
    ciphername_len: usize,
    kdfname_offset: usize,
    kdfname_len: usize,
    kdf_offset: usize,
    kdf_len: usize,
    public_key_offset: usize,
    public_key_len: usize,
    encrypted_offset: usize,
    encrypted_len: usize,
    bcrypt_salt_offset: usize,
    bcrypt_salt_len: usize,
    bcrypt_rounds: u32,
    kdf_kind: u32,
}

#[repr(C)]
pub struct RustPrivate2PlaintextParse {
    key_kind: u32,
    curve_nid: c_int,
    is_cert: u32,
    cert_offset: usize,
    cert_len: usize,
    comment_offset: usize,
    comment_len: usize,
    part1_offset: usize,
    part1_len: usize,
    part2_offset: usize,
    part2_len: usize,
    part3_offset: usize,
    part3_len: usize,
    part4_offset: usize,
    part4_len: usize,
    part5_offset: usize,
    part5_len: usize,
    part6_offset: usize,
    part6_len: usize,
}

#[repr(C)]
pub struct RustPublicLineParse {
    key_type_offset: usize,
    key_type_len: usize,
    key_blob_offset: usize,
    key_blob_len: usize,
    comment_offset: usize,
}

#[repr(C)]
pub struct RustArgvSplitParse {
    argc: usize,
    packed_len: usize,
}

#[repr(C)]
pub struct RustStrdelimParse {
    next_offset: usize,
    next_is_null: u32,
}

#[repr(C)]
pub struct RustHpdelimParse {
    next_offset: usize,
    next_is_null: u32,
    delim: u8,
}

#[repr(C)]
pub struct RustForwardFieldParse {
    arg_offset: usize,
    next_offset: usize,
    ispath: u32,
}

#[repr(C)]
pub struct RustForwardParse {
    field_count: u32,
    listen_host_offset: usize,
    listen_host_len: usize,
    listen_port_offset: usize,
    listen_port_len: usize,
    listen_path_offset: usize,
    listen_path_len: usize,
    connect_host_offset: usize,
    connect_host_len: usize,
    connect_port_offset: usize,
    connect_port_len: usize,
    connect_path_offset: usize,
    connect_path_len: usize,
    has_listen_host: u32,
    has_listen_port: u32,
    has_listen_path: u32,
    has_connect_host: u32,
    has_connect_host_socks: u32,
    has_connect_port: u32,
    has_connect_path: u32,
    listen_port_value: i32,
    connect_port_value: i32,
}

#[repr(C)]
pub struct RustJumpParse {
    first_offset: usize,
    first_len: usize,
    extra_len: usize,
    is_none: u32,
    first_is_uri: u32,
    has_extra: u32,
}

#[repr(C)]
pub struct RustHostfileLineParse {
    kind: u32,
    marker: u32,
    hosts_offset: usize,
    hosts_len: usize,
    rawkey_offset: usize,
    keytype_offset: usize,
    keytype_len: usize,
}

#[repr(C)]
pub struct RustUserHostPortParse {
    user_offset: usize,
    user_len: usize,
    host_offset: usize,
    host_len: usize,
    port_offset: usize,
    port_len: usize,
    has_user: u32,
    has_port: u32,
}

#[repr(C)]
pub struct RustUriParse {
    user_offset: usize,
    user_len: usize,
    host_offset: usize,
    host_len: usize,
    port_offset: usize,
    port_len: usize,
    path_offset: usize,
    path_len: usize,
    has_user: u32,
    has_port: u32,
    has_path: u32,
}

#[repr(C)]
pub struct RustUserHostPathParse {
    user_offset: usize,
    user_len: usize,
    host_offset: usize,
    host_len: usize,
    path_offset: usize,
    path_len: usize,
    has_user: u32,
}

#[repr(C)]
pub struct RustPatternIntervalParse {
    type_len: usize,
    interval_offset: usize,
    interval_len: usize,
}

#[repr(C)]
pub struct RustOptDequoteParse {
    output_len: usize,
    next_offset: usize,
}

#[repr(C)]
pub struct RustDollarExpandParse {
    output_len: usize,
    missing_var: u32,
}

#[repr(C)]
pub struct RustFmtIntArgParse {
    literal: c_int,
    index: usize,
}

#[repr(C)]
pub struct RustForwardFormatParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustStrarrayOnelineParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustPermitListLineParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustStrarrayLinesParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustCfgStringParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustCfgIntParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustListenaddrLineParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustIpqosLineParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustTunneldeviceLineParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustAddKeysToAgentLineParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustForwardAgentLineParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustAllowedCnameEntry {
    source_list: *const c_char,
    target_list: *const c_char,
}

#[repr(C)]
pub struct RustCanonicalizePermittedCnamesLineParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustProxyjumpLineParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustRekeyLimitLineParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustControlPersistLineParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustConnectTimeoutLineParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustPubkeyAuthOptionsLineParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustPermitUserEnvironmentLineParse {
    output_len: usize,
    emit: u32,
}

#[repr(C)]
pub struct RustEscapeCharLineParse {
    output_len: usize,
    emit: u32,
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_cert_parse_body(
    input: *const u8,
    input_len: usize,
    out: *mut RustCertBodyParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(input) = read_slice(input, input_len) else {
        return -1;
    };
    let Some(parsed) = parse_cert_body(input) else {
        return -1;
    };
    unsafe {
        *out = RustCertBodyParse {
            serial: parsed.serial,
            cert_type: parsed.cert_type,
            valid_after: parsed.valid_after,
            valid_before: parsed.valid_before,
            signed_consumed: parsed.signed_consumed,
            total_consumed: parsed.total_consumed,
            key_id_offset: parsed.key_id_offset,
            key_id_len: parsed.key_id_len,
            principals_offset: parsed.principals_offset,
            principals_len: parsed.principals_len,
            critical_offset: parsed.critical_offset,
            critical_len: parsed.critical_len,
            extensions_offset: parsed.extensions_offset,
            extensions_len: parsed.extensions_len,
            ca_key_offset: parsed.ca_key_offset,
            ca_key_len: parsed.ca_key_len,
            signature_offset: parsed.signature_offset,
            signature_len: parsed.signature_len,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_private2_decode_len(input: *const u8, input_len: usize) -> usize {
    openssh_private2_decode_len(input, input_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_private2_decode_write(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    openssh_private2_decode_write(input, input_len, out, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_private2_parse_header(
    decoded: *const u8,
    decoded_len: usize,
    out: *mut RustPrivate2HeaderParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = openssh_private2_parse(decoded, decoded_len) else {
        return -1;
    };
    unsafe {
        *out = RustPrivate2HeaderParse {
            ciphername_offset: parsed.ciphername_offset,
            ciphername_len: parsed.ciphername_len,
            kdfname_offset: parsed.kdfname_offset,
            kdfname_len: parsed.kdfname_len,
            kdf_offset: parsed.kdf_offset,
            kdf_len: parsed.kdf_len,
            public_key_offset: parsed.public_key_offset,
            public_key_len: parsed.public_key_len,
            encrypted_offset: parsed.encrypted_offset,
            encrypted_len: parsed.encrypted_len,
            bcrypt_salt_offset: parsed.bcrypt_salt_offset,
            bcrypt_salt_len: parsed.bcrypt_salt_len,
            bcrypt_rounds: parsed.bcrypt_rounds,
            kdf_kind: parsed.kdf_kind,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_private2_parse_plaintext(
    decrypted: *const u8,
    decrypted_len: usize,
    out: *mut RustPrivate2PlaintextParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = openssh_private2_parse_plaintext(decrypted, decrypted_len) else {
        return -1;
    };
    unsafe {
        *out = RustPrivate2PlaintextParse {
            key_kind: parsed.key_kind,
            curve_nid: parsed.curve_nid,
            is_cert: parsed.is_cert,
            cert_offset: parsed.cert_offset,
            cert_len: parsed.cert_len,
            comment_offset: parsed.comment_offset,
            comment_len: parsed.comment_len,
            part1_offset: parsed.part1_offset,
            part1_len: parsed.part1_len,
            part2_offset: parsed.part2_offset,
            part2_len: parsed.part2_len,
            part3_offset: parsed.part3_offset,
            part3_len: parsed.part3_len,
            part4_offset: parsed.part4_offset,
            part4_len: parsed.part4_len,
            part5_offset: parsed.part5_offset,
            part5_len: parsed.part5_len,
            part6_offset: parsed.part6_offset,
            part6_len: parsed.part6_len,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_public_line_parse(
    input: *const u8,
    input_len: usize,
    out: *mut RustPublicLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = openssh_public_line_parse(input, input_len) else {
        return -1;
    };
    unsafe {
        *out = RustPublicLineParse {
            key_type_offset: parsed.key_type_offset,
            key_type_len: parsed.key_type_len,
            key_blob_offset: parsed.key_blob_offset,
            key_blob_len: parsed.key_blob_len,
            comment_offset: parsed.comment_offset,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_public_blob_decode_len(input: *const u8, input_len: usize) -> usize {
    openssh_public_blob_decode_len(input, input_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_public_blob_decode_write(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    openssh_public_blob_decode_write(input, input_len, out, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_argv_split_parse(
    input: *const u8,
    input_len: usize,
    terminate_on_comment: c_int,
    out: *mut RustArgvSplitParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = argv_split_parse(input, input_len, terminate_on_comment) else {
        return -1;
    };
    unsafe {
        *out = RustArgvSplitParse {
            argc: parsed.argc,
            packed_len: parsed.packed_len,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_argv_split_write(
    input: *const u8,
    input_len: usize,
    terminate_on_comment: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    argv_split_write(input, input_len, terminate_on_comment, out, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_strdelim_parse(
    input: *mut u8,
    input_len: usize,
    split_equals: c_int,
    out: *mut RustStrdelimParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = strdelim_parse_in_place(input, input_len, split_equals) else {
        return -1;
    };
    unsafe {
        *out = RustStrdelimParse {
            next_offset: parsed.next_offset,
            next_is_null: parsed.next_is_null,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_hpdelim2_parse(
    input: *mut u8,
    input_len: usize,
    out: *mut RustHpdelimParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = util::hpdelim2_parse_in_place(input, input_len) else {
        return -1;
    };
    unsafe {
        *out = RustHpdelimParse {
            next_offset: parsed.next_offset,
            next_is_null: parsed.next_is_null,
            delim: parsed.delim,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_parse_forward_field(
    input: *mut u8,
    input_len: usize,
    out: *mut RustForwardFieldParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = parse_forward_field_in_place(input, input_len) else {
        return -1;
    };
    unsafe {
        *out = RustForwardFieldParse {
            arg_offset: parsed.arg_offset,
            next_offset: parsed.next_offset,
            ispath: parsed.ispath,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_parse_forward(
    input: *mut u8,
    input_len: usize,
    dynamicfwd: c_int,
    remotefwd: c_int,
    out: *mut RustForwardParse,
) -> c_int {
    let Some(parsed) = parse_forward_in_place(input, input_len, dynamicfwd, remotefwd) else {
        return -1;
    };
    if out.is_null() {
        return -1;
    }
    unsafe {
        *out = RustForwardParse {
            field_count: parsed.field_count,
            listen_host_offset: parsed.listen_host_offset,
            listen_host_len: parsed.listen_host_len,
            listen_port_offset: parsed.listen_port_offset,
            listen_port_len: parsed.listen_port_len,
            listen_path_offset: parsed.listen_path_offset,
            listen_path_len: parsed.listen_path_len,
            connect_host_offset: parsed.connect_host_offset,
            connect_host_len: parsed.connect_host_len,
            connect_port_offset: parsed.connect_port_offset,
            connect_port_len: parsed.connect_port_len,
            connect_path_offset: parsed.connect_path_offset,
            connect_path_len: parsed.connect_path_len,
            has_listen_host: parsed.has_listen_host,
            has_listen_port: parsed.has_listen_port,
            has_listen_path: parsed.has_listen_path,
            has_connect_host: parsed.has_connect_host,
            has_connect_host_socks: parsed.has_connect_host_socks,
            has_connect_port: parsed.has_connect_port,
            has_connect_path: parsed.has_connect_path,
            listen_port_value: parsed.listen_port_value,
            connect_port_value: parsed.connect_port_value,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_parse_jump(
    input: *const u8,
    input_len: usize,
    out: *mut RustJumpParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = parse_jump(input, input_len) else {
        return -1;
    };
    unsafe {
        *out = RustJumpParse {
            first_offset: parsed.first_offset,
            first_len: parsed.first_len,
            extra_len: parsed.extra_len,
            is_none: parsed.is_none,
            first_is_uri: parsed.first_is_uri,
            has_extra: parsed.has_extra,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_parse_hostfile_line(
    input: *const u8,
    input_len: usize,
    out: *mut RustHostfileLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = parse_hostfile_line(input, input_len) else {
        return -1;
    };
    unsafe {
        *out = RustHostfileLineParse {
            kind: parsed.kind,
            marker: parsed.marker,
            hosts_offset: parsed.hosts_offset,
            hosts_len: parsed.hosts_len,
            rawkey_offset: parsed.rawkey_offset,
            keytype_offset: parsed.keytype_offset,
            keytype_len: parsed.keytype_len,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_host_hash(
    host: *const u8,
    host_len: usize,
    name_from_hostfile: *const u8,
    src_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    host_hash_write(host, host_len, name_from_hostfile, src_len, out, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_match_hashed_host(
    host: *const u8,
    host_len: usize,
    names: *const u8,
    names_len: usize,
) -> c_int {
    match_hashed_host(host, host_len, names, names_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_parse_user_host_port(
    input: *const u8,
    input_len: usize,
    out: *mut RustUserHostPortParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = util::parse_user_host_port(input, input_len) else {
        return -1;
    };
    unsafe {
        *out = RustUserHostPortParse {
            user_offset: parsed.user_offset,
            user_len: parsed.user_len,
            host_offset: parsed.host_offset,
            host_len: parsed.host_len,
            port_offset: parsed.port_offset,
            port_len: parsed.port_len,
            has_user: parsed.has_user,
            has_port: parsed.has_port,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_parse_uri(
    input: *const u8,
    input_len: usize,
    out: *mut RustUriParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = util::parse_uri(input, input_len) else {
        return -1;
    };
    unsafe {
        *out = RustUriParse {
            user_offset: parsed.user_offset,
            user_len: parsed.user_len,
            host_offset: parsed.host_offset,
            host_len: parsed.host_len,
            port_offset: parsed.port_offset,
            port_len: parsed.port_len,
            path_offset: parsed.path_offset,
            path_len: parsed.path_len,
            has_user: parsed.has_user,
            has_port: parsed.has_port,
            has_path: parsed.has_path,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_parse_user_host_path(
    input: *const u8,
    input_len: usize,
    out: *mut RustUserHostPathParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = util::parse_user_host_path(input, input_len) else {
        return -1;
    };
    unsafe {
        *out = RustUserHostPathParse {
            user_offset: parsed.user_offset,
            user_len: parsed.user_len,
            host_offset: parsed.host_offset,
            host_len: parsed.host_len,
            path_offset: parsed.path_offset,
            path_len: parsed.path_len,
            has_user: parsed.has_user,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_validate_permit(
    input: *const u8,
    input_len: usize,
    allow_bare_port: c_int,
) -> c_int {
    if validate_permit(input, input_len, allow_bare_port) {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_parse_ipqos(
    input: *const u8,
    input_len: usize,
    out: *mut c_int,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = parse_ipqos(input, input_len) else {
        return -1;
    };
    unsafe {
        *out = parsed;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_a2port(
    input: *const u8,
    input_len: usize,
    out: *mut c_int,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = a2port(input, input_len) else {
        return -1;
    };
    unsafe {
        *out = parsed;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_atoi_err(
    input: *const u8,
    input_len: usize,
    out: *mut c_int,
    status: *mut c_int,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match atoi_err(input, input_len) {
        Ok(parsed) => {
            store_parse_status(status, OSSH_RUST_PARSE_STATUS_OK);
            unsafe {
                *out = parsed;
            }
            0
        }
        Err(err) => {
            let mapped = match err {
                ATOI_STATUS_MISSING => OSSH_RUST_ATOI_STATUS_MISSING,
                ATOI_STATUS_TOO_SMALL => OSSH_RUST_ATOI_STATUS_TOO_SMALL,
                ATOI_STATUS_TOO_LARGE => OSSH_RUST_ATOI_STATUS_TOO_LARGE,
                _ => OSSH_RUST_ATOI_STATUS_INVALID,
            };
            store_parse_status(status, mapped);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_multistate_lookup(
    input: *const u8,
    input_len: usize,
    entries: *const RustMultistateEntry,
    nentries: usize,
    out: *mut c_int,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match multistate_lookup(input, input_len, entries, nentries) {
        Some(parsed) => {
            unsafe {
                *out = parsed;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_multistate_name(
    value: c_int,
    entries: *const RustMultistateEntry,
    nentries: usize,
    out_index: *mut usize,
) -> c_int {
    if out_index.is_null() {
        return -1;
    }
    match multistate_name(value, entries, nentries) {
        Some(index) => {
            unsafe {
                *out_index = index;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_fmt_intarg(
    value: c_int,
    mode: c_int,
    entries: *const RustMultistateEntry,
    nentries: usize,
    out: *mut RustFmtIntArgParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match fmt_intarg_parse(value, mode, entries, nentries) {
        Some(parsed) => {
            unsafe {
                *out = RustFmtIntArgParse {
                    literal: parsed.literal,
                    index: parsed.index,
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_forward_format_parse(
    mode: c_int,
    listen_host: *const c_char,
    listen_port: c_int,
    listen_path: *const c_char,
    connect_host: *const c_char,
    connect_port: c_int,
    connect_path: *const c_char,
    out: *mut RustForwardFormatParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match forward_format_parse(
        mode,
        listen_host,
        listen_port,
        listen_path,
        connect_host,
        connect_port,
        connect_path,
    ) {
        Some(parsed) => {
            unsafe {
                *out = RustForwardFormatParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_forward_format_write(
    mode: c_int,
    listen_host: *const c_char,
    listen_port: c_int,
    listen_path: *const c_char,
    connect_host: *const c_char,
    connect_port: c_int,
    connect_path: *const c_char,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if forward_format_write(
        mode,
        listen_host,
        listen_port,
        listen_path,
        connect_host,
        connect_port,
        connect_path,
        out,
        out_len,
    )
    .is_some()
    {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_strarray_oneline_parse(
    vals: *const *const c_char,
    nvals: usize,
    empty_mode: u32,
    out: *mut RustStrarrayOnelineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match strarray_oneline_parse(vals, nvals, empty_mode) {
        Some(parsed) => {
            unsafe {
                *out = RustStrarrayOnelineParse {
                    output_len: parsed.output_len,
                    emit: if parsed.emit { 1 } else { 0 },
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_strarray_oneline_write(
    vals: *const *const c_char,
    nvals: usize,
    empty_mode: u32,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if strarray_oneline_write(vals, nvals, empty_mode, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_permit_list_line_parse(
    prefix: *const c_char,
    vals: *const *const c_char,
    nvals: usize,
    out: *mut RustPermitListLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match permit_list_line_parse(prefix, vals, nvals) {
        Some(parsed) => {
            unsafe {
                *out = RustPermitListLineParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_permit_list_line_write(
    prefix: *const c_char,
    vals: *const *const c_char,
    nvals: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if permit_list_line_write(prefix, vals, nvals, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_strarray_lines_parse(
    prefix: *const c_char,
    vals: *const *const c_char,
    nvals: usize,
    out: *mut RustStrarrayLinesParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match strarray_lines_parse(prefix, vals, nvals) {
        Some(parsed) => {
            unsafe {
                *out = RustStrarrayLinesParse {
                    output_len: parsed.output_len,
                    emit: if parsed.emit { 1 } else { 0 },
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_strarray_lines_write(
    prefix: *const c_char,
    vals: *const *const c_char,
    nvals: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if strarray_lines_write(prefix, vals, nvals, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_cfg_string_parse(
    prefix: *const c_char,
    value: *const c_char,
    empty_mode: u32,
    out: *mut RustCfgStringParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match cfg_string_parse(prefix, value, empty_mode) {
        Some(parsed) => {
            unsafe {
                *out = RustCfgStringParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_cfg_string_write(
    prefix: *const c_char,
    value: *const c_char,
    empty_mode: u32,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if cfg_string_write(prefix, value, empty_mode, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_cfg_int_parse(
    prefix: *const c_char,
    value: c_int,
    mode: u32,
    out: *mut RustCfgIntParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match cfg_int_parse(prefix, value, mode) {
        Some(parsed) => {
            unsafe {
                *out = RustCfgIntParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_cfg_int_write(
    prefix: *const c_char,
    value: c_int,
    mode: u32,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if cfg_int_write(prefix, value, mode, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_listenaddr_line_parse(
    addr: *const c_char,
    port: *const c_char,
    rdomain: *const c_char,
    is_ipv6: u32,
    out: *mut RustListenaddrLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match listenaddr_line_parse(addr, port, rdomain, is_ipv6 != 0) {
        Some(parsed) => {
            unsafe {
                *out = RustListenaddrLineParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_listenaddr_line_write(
    addr: *const c_char,
    port: *const c_char,
    rdomain: *const c_char,
    is_ipv6: u32,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if listenaddr_line_write(addr, port, rdomain, is_ipv6 != 0, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ipqos_line_parse(
    interactive: c_int,
    bulk: c_int,
    out: *mut RustIpqosLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match ipqos_line_parse(interactive, bulk) {
        Some(parsed) => {
            unsafe {
                *out = RustIpqosLineParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ipqos_line_write(
    interactive: c_int,
    bulk: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if ipqos_line_write(interactive, bulk, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_tunneldevice_line_parse(
    local: c_int,
    remote: c_int,
    out: *mut RustTunneldeviceLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match tunneldevice_line_parse(local, remote) {
        Some(parsed) => {
            unsafe {
                *out = RustTunneldeviceLineParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_tunneldevice_line_write(
    local: c_int,
    remote: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if tunneldevice_line_write(local, remote, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_add_keys_to_agent_line_parse(
    mode: c_int,
    lifespan: c_int,
    out: *mut RustAddKeysToAgentLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match add_keys_to_agent_line_parse(mode, lifespan) {
        Some(parsed) => {
            unsafe {
                *out = RustAddKeysToAgentLineParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_add_keys_to_agent_line_write(
    mode: c_int,
    lifespan: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if add_keys_to_agent_line_write(mode, lifespan, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_forwardagent_line_parse(
    value: c_int,
    socket_path: *const c_char,
    out: *mut RustForwardAgentLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match forwardagent_line_parse(value, socket_path) {
        Some(parsed) => {
            unsafe {
                *out = RustForwardAgentLineParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_forwardagent_line_write(
    value: c_int,
    socket_path: *const c_char,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if forwardagent_line_write(value, socket_path, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_canonicalize_permitted_cnames_line_parse(
    entries: *const RustAllowedCnameEntry,
    nentries: usize,
    out: *mut RustCanonicalizePermittedCnamesLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match canonicalize_permitted_cnames_line_parse(entries.cast::<AllowedCnameEntry>(), nentries) {
        Some(parsed) => {
            unsafe {
                *out = RustCanonicalizePermittedCnamesLineParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_canonicalize_permitted_cnames_line_write(
    entries: *const RustAllowedCnameEntry,
    nentries: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if canonicalize_permitted_cnames_line_write(
        entries.cast::<AllowedCnameEntry>(),
        nentries,
        out,
        out_len,
    )
    .is_some()
    {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_proxyjump_line_parse(
    extra: *const c_char,
    user: *const c_char,
    host: *const c_char,
    port: c_int,
    out: *mut RustProxyjumpLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match proxyjump_line_parse(extra, user, host, port) {
        Some(parsed) => {
            unsafe {
                *out = RustProxyjumpLineParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_proxyjump_line_write(
    extra: *const c_char,
    user: *const c_char,
    host: *const c_char,
    port: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if proxyjump_line_write(extra, user, host, port, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rekeylimit_line_parse(
    limit: u64,
    interval: c_int,
    out: *mut RustRekeyLimitLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match rekeylimit_line_parse(limit, interval) {
        Some(parsed) => {
            unsafe {
                *out = RustRekeyLimitLineParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rekeylimit_line_write(
    limit: u64,
    interval: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if rekeylimit_line_write(limit, interval, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_controlpersist_line_parse(
    value: c_int,
    timeout: c_int,
    out: *mut RustControlPersistLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match controlpersist_line_parse(value, timeout) {
        Some(parsed) => {
            unsafe {
                *out = RustControlPersistLineParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_controlpersist_line_write(
    value: c_int,
    timeout: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if controlpersist_line_write(value, timeout, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_connecttimeout_line_parse(
    value: c_int,
    out: *mut RustConnectTimeoutLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match connecttimeout_line_parse(value) {
        Some(parsed) => {
            unsafe {
                *out = RustConnectTimeoutLineParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_connecttimeout_line_write(
    value: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if connecttimeout_line_write(value, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_pubkeyauthoptions_line_parse(
    value: c_int,
    out: *mut RustPubkeyAuthOptionsLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match pubkeyauthoptions_line_parse(value) {
        Some(parsed) => {
            unsafe {
                *out = RustPubkeyAuthOptionsLineParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_pubkeyauthoptions_line_write(
    value: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if pubkeyauthoptions_line_write(value, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_permituserenvironment_line_parse(
    value: c_int,
    allowlist: *const c_char,
    out: *mut RustPermitUserEnvironmentLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match permituserenvironment_line_parse(value, allowlist) {
        Some(parsed) => {
            unsafe {
                *out = RustPermitUserEnvironmentLineParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_permituserenvironment_line_write(
    value: c_int,
    allowlist: *const c_char,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if permituserenvironment_line_write(value, allowlist, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_escapechar_line_parse(
    value: c_int,
    out: *mut RustEscapeCharLineParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match escapechar_line_parse(value) {
        Some(parsed) => {
            unsafe {
                *out = RustEscapeCharLineParse {
                    output_len: parsed.output_len,
                    emit: u32::from(parsed.emit),
                };
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_escapechar_line_write(
    value: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if escapechar_line_write(value, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_keyword_lookup(
    input: *const u8,
    input_len: usize,
    entries: *const RustKeywordEntry,
    nentries: usize,
    ignore_case: c_int,
    out: *mut c_int,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match keyword_lookup(input, input_len, entries, nentries, ignore_case != 0) {
        Some(parsed) => {
            unsafe {
                *out = parsed;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_keyword_name(
    value: c_int,
    entries: *const RustKeywordEntry,
    nentries: usize,
    out_index: *mut usize,
) -> c_int {
    if out_index.is_null() {
        return -1;
    }
    match keyword_name(value, entries, nentries) {
        Some(index) => {
            unsafe {
                *out_index = index;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_type_from_name(
    input: *const u8,
    input_len: usize,
    entries: *const *const RustSshkeyImplEntry,
    nentries: usize,
    allow_short: c_int,
    out: *mut c_int,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match rust_sshkey_type_from_name(input, input_len, entries, nentries, allow_short != 0) {
        Some(parsed) => {
            unsafe {
                *out = parsed;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_impl_name_from_type_nid(
    type_: c_int,
    nid: c_int,
    want_short: c_int,
    entries: *const *const RustSshkeyImplEntry,
    nentries: usize,
    out: *mut *const c_char,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match rust_sshkey_impl_name_from_type_nid(type_, nid, want_short != 0, entries, nentries) {
        Some(parsed) => {
            unsafe {
                *out = parsed;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_impl_index_from_type(
    type_: c_int,
    entries: *const *const RustSshkeyImplEntry,
    nentries: usize,
    out: *mut usize,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match rust_sshkey_impl_index_from_type(type_, entries, nentries) {
        Some(parsed) => {
            unsafe {
                *out = parsed;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_impl_index_from_type_nid(
    type_: c_int,
    nid: c_int,
    entries: *const *const RustSshkeyImplEntry,
    nentries: usize,
    out: *mut usize,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match rust_sshkey_impl_index_from_type_nid(type_, nid, entries, nentries) {
        Some(parsed) => {
            unsafe {
                *out = parsed;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_ecdsa_nid_from_name(
    input: *const u8,
    input_len: usize,
    entries: *const *const RustSshkeyImplEntry,
    nentries: usize,
    out: *mut c_int,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match rust_sshkey_ecdsa_nid_from_name(input, input_len, entries, nentries) {
        Some(parsed) => {
            unsafe {
                *out = parsed;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_type_is_valid_ca(
    type_: c_int,
    entries: *const *const RustSshkeyImplEntry,
    nentries: usize,
    out: *mut c_int,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match rust_sshkey_type_is_valid_ca(type_, entries, nentries) {
        Some(parsed) => {
            unsafe {
                *out = c_int::from(parsed);
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_type_is_cert(type_: c_int, out: *mut c_int) -> c_int {
    if out.is_null() {
        return -1;
    }
    unsafe {
        *out = c_int::from(rust_sshkey_type_is_cert(type_));
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_type_plain(type_: c_int, out: *mut c_int) -> c_int {
    if out.is_null() {
        return -1;
    }
    unsafe {
        *out = rust_sshkey_type_plain(type_);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_type_certified(type_: c_int, out: *mut c_int) -> c_int {
    if out.is_null() {
        return -1;
    }
    match rust_sshkey_type_certified(type_) {
        Some(parsed) => {
            unsafe {
                *out = parsed;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_type_is_sk(type_: c_int, out: *mut c_int) -> c_int {
    if out.is_null() {
        return -1;
    }
    unsafe {
        *out = c_int::from(rust_sshkey_type_is_sk(type_));
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_type_can_new(
    type_: c_int,
    entries: *const *const RustSshkeyImplEntry,
    nentries: usize,
    out: *mut c_int,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match rust_sshkey_type_can_new(type_, entries, nentries) {
        Some(parsed) => {
            unsafe {
                *out = c_int::from(parsed);
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_generate_plan(
    type_: c_int,
    entries: *const *const RustSshkeyImplEntry,
    nentries: usize,
    out_type: *mut c_int,
) -> c_int {
    if out_type.is_null() {
        return -1;
    }
    match rust_sshkey_generate_plan(type_, entries, nentries) {
        Ok(effective_type) => {
            unsafe {
                *out_type = effective_type;
            }
            0
        }
        Err(err) => err,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_serialize_plan(
    type_: c_int,
    force_plain: c_int,
    has_cert: c_int,
    certblob_len: usize,
    out_type: *mut c_int,
    out_use_cert_blob: *mut c_int,
) -> c_int {
    if out_type.is_null() || out_use_cert_blob.is_null() {
        return -1;
    }
    match rust_sshkey_serialize_plan(type_, force_plain != 0, has_cert != 0, certblob_len) {
        Ok((effective_type, use_cert_blob)) => {
            unsafe {
                *out_type = effective_type;
                *out_use_cert_blob = c_int::from(use_cert_blob);
            }
            0
        }
        Err(err) => err,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_from_private_plan(
    type_: c_int,
    nid: c_int,
    entries: *const *const RustSshkeyImplEntry,
    nentries: usize,
    out_type: *mut c_int,
    out_copy_cert: *mut c_int,
) -> c_int {
    if out_type.is_null() || out_copy_cert.is_null() {
        return -1;
    }
    match rust_sshkey_from_private_plan(type_, nid, entries, nentries) {
        Some((out_type_value, copy_cert)) => {
            unsafe {
                *out_type = out_type_value;
                *out_copy_cert = c_int::from(copy_cert);
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_equal_public_plan(
    lhs_type: c_int,
    rhs_type: c_int,
    entries: *const *const RustSshkeyImplEntry,
    nentries: usize,
    out_comparable: *mut c_int,
    out_dispatch_type: *mut c_int,
) -> c_int {
    if out_comparable.is_null() || out_dispatch_type.is_null() {
        return -1;
    }
    match rust_sshkey_equal_public_plan(lhs_type, rhs_type, entries, nentries) {
        Some((comparable, dispatch_type)) => {
            unsafe {
                *out_comparable = c_int::from(comparable);
                *out_dispatch_type = dispatch_type;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_equal_plan(
    lhs_type: c_int,
    rhs_type: c_int,
    entries: *const *const RustSshkeyImplEntry,
    nentries: usize,
    out_compare_cert: *mut c_int,
    out_dispatch_type: *mut c_int,
) -> c_int {
    if out_compare_cert.is_null() || out_dispatch_type.is_null() {
        return -1;
    }
    match rust_sshkey_equal_plan(lhs_type, rhs_type, entries, nentries) {
        Some((compare_cert, dispatch_type)) => {
            unsafe {
                *out_compare_cert = c_int::from(compare_cert);
                *out_dispatch_type = dispatch_type;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_from_blob_plan(
    input: *const u8,
    input_len: usize,
    allow_cert: c_int,
    entries: *const *const RustSshkeyImplEntry,
    nentries: usize,
    out_type: *mut c_int,
    out_impl_index: *mut c_int,
    out_use_noec_fallback: *mut c_int,
) -> c_int {
    if out_type.is_null() || out_impl_index.is_null() || out_use_noec_fallback.is_null() {
        return -1;
    }
    match rust_sshkey_from_blob_plan(input, input_len, allow_cert != 0, entries, nentries) {
        Ok((type_, impl_index, use_noec_fallback)) => {
            unsafe {
                *out_type = type_;
                *out_impl_index = impl_index;
                *out_use_noec_fallback = c_int::from(use_noec_fallback);
            }
            0
        }
        Err(err) => err,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sshkey_free_contents_plan(
    type_: c_int,
    entries: *const *const RustSshkeyImplEntry,
    nentries: usize,
    out_has_cert: *mut c_int,
    out_impl_index: *mut c_int,
) -> c_int {
    if out_has_cert.is_null() || out_impl_index.is_null() {
        return -1;
    }
    match rust_sshkey_free_contents_plan(type_, entries, nentries) {
        Some((has_cert, impl_index)) => {
            unsafe {
                *out_has_cert = c_int::from(has_cert);
                *out_impl_index = impl_index;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_opt_flag(
    opt: *const u8,
    opt_len: usize,
    allow_negate: c_int,
    input: *const u8,
    input_len: usize,
    out_offset: *mut usize,
    out_result: *mut c_int,
) -> c_int {
    if out_offset.is_null() || out_result.is_null() {
        return -1;
    }
    match opt_flag_parse(opt, opt_len, allow_negate != 0, input, input_len) {
        Some((offset, result)) => {
            unsafe {
                *out_offset = offset;
                *out_result = result;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_lookup_env_in_list(
    env: *const u8,
    env_len: usize,
    envs: *const *const c_char,
    nenvs: usize,
    out_index: *mut usize,
    out_value_offset: *mut usize,
) -> c_int {
    if out_index.is_null() || out_value_offset.is_null() {
        return -1;
    }
    match lookup_env_in_list_parse(env, env_len, envs, nenvs) {
        Some((index, offset)) => {
            unsafe {
                *out_index = index;
                *out_value_offset = offset;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_lookup_setenv_in_list(
    env: *const u8,
    env_len: usize,
    envs: *const *const c_char,
    nenvs: usize,
    out_index: *mut usize,
    out_value_offset: *mut usize,
) -> c_int {
    if out_index.is_null() || out_value_offset.is_null() {
        return -1;
    }
    match lookup_setenv_in_list_parse(env, env_len, envs, nenvs) {
        Some((index, offset)) => {
            unsafe {
                *out_index = index;
                *out_value_offset = offset;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_opt_match(
    term: *const u8,
    term_len: usize,
    input: *const u8,
    input_len: usize,
    out_offset: *mut usize,
    out_result: *mut c_int,
) -> c_int {
    if out_offset.is_null() || out_result.is_null() {
        return -1;
    }
    match opt_match_parse(term, term_len, input, input_len) {
        Some((offset, result)) => {
            unsafe {
                *out_offset = offset;
                *out_result = result;
            }
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_opt_dequote_parse(
    input: *const u8,
    input_len: usize,
    out: *mut RustOptDequoteParse,
    status: *mut c_int,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match opt_dequote_parse(input, input_len) {
        Ok(parsed) => {
            store_parse_status(status, OSSH_RUST_PARSE_STATUS_OK);
            unsafe {
                *out = RustOptDequoteParse {
                    output_len: parsed.output_len,
                    next_offset: parsed.next_offset,
                };
            }
            0
        }
        Err(err) => {
            let mapped = match err {
                OPT_DEQUOTE_MISSING_START => OSSH_RUST_OPT_DEQUOTE_MISSING_START,
                _ => OSSH_RUST_OPT_DEQUOTE_MISSING_END,
            };
            store_parse_status(status, mapped);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_opt_dequote_write(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if opt_dequote_write(input, input_len, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_dollar_expand_parse(
    input: *const u8,
    input_len: usize,
    out: *mut RustDollarExpandParse,
    status: *mut c_int,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    match dollar_expand_parse(input, input_len) {
        Ok(parsed) => {
            store_parse_status(status, OSSH_RUST_PARSE_STATUS_OK);
            unsafe {
                *out = RustDollarExpandParse {
                    output_len: parsed.output_len,
                    missing_var: parsed.missing_var.into(),
                };
            }
            0
        }
        Err(_) => {
            store_parse_status(status, OSSH_RUST_DOLLAR_EXPAND_INVALID);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_dollar_expand_write(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if dollar_expand_write(input, input_len, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_expand_parse(
    input: *const u8,
    input_len: usize,
    flags: u32,
    entries: *const RustExpandEntry,
    nentries: usize,
    out: *mut RustDollarExpandParse,
    status: *mut c_int,
) -> c_int {
    if out.is_null() {
        store_parse_status(status, OSSH_RUST_DOLLAR_EXPAND_INVALID);
        return -1;
    }
    match expand_parse(input, input_len, flags, entries, nentries) {
        Ok(parsed) => {
            unsafe {
                *out = RustDollarExpandParse {
                    output_len: parsed.output_len,
                    missing_var: u32::from(parsed.missing_var),
                };
            }
            store_parse_status(status, OSSH_RUST_PARSE_STATUS_OK);
            0
        }
        Err(err) => {
            store_parse_status(status, err);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_expand_write(
    input: *const u8,
    input_len: usize,
    flags: u32,
    entries: *const RustExpandEntry,
    nentries: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if expand_write(input, input_len, flags, entries, nentries, out, out_len).is_some() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_valid_env_name(input: *const u8, input_len: usize) -> c_int {
    if valid_env_name(input, input_len) {
        1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_valid_domain(
    input: *mut u8,
    input_len: usize,
    makelower: c_int,
    status: *mut c_int,
) -> c_int {
    match valid_domain(input, input_len, makelower) {
        Ok(()) => {
            store_parse_status(status, OSSH_RUST_PARSE_STATUS_OK);
            0
        }
        Err(err) => {
            let mapped = match err {
                DOMAIN_STATUS_EMPTY => OSSH_RUST_DOMAIN_STATUS_EMPTY,
                DOMAIN_STATUS_START_INVALID => OSSH_RUST_DOMAIN_STATUS_START_INVALID,
                DOMAIN_STATUS_CONSECUTIVE_SEPARATORS => {
                    OSSH_RUST_DOMAIN_STATUS_CONSECUTIVE_SEPARATORS
                }
                _ => OSSH_RUST_DOMAIN_STATUS_INVALID_CHARS,
            };
            store_parse_status(status, mapped);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_parse_absolute_time(
    input: *const u8,
    input_len: usize,
    tp: *mut u64,
) -> c_int {
    if tp.is_null() {
        return -1;
    }
    let Some(parsed) = util::parse_absolute_time(input, input_len) else {
        return -1;
    };
    unsafe {
        *tp = parsed;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_convtime_double(
    input: *const u8,
    input_len: usize,
    out: *mut c_double,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = parse_convtime_double(input, input_len) else {
        return -1;
    };
    unsafe {
        *out = parsed;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_parse_pattern_interval(
    input: *const u8,
    input_len: usize,
    out: *mut RustPatternIntervalParse,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let Some(parsed) = parse_pattern_interval(input, input_len) else {
        return -1;
    };
    unsafe {
        *out = RustPatternIntervalParse {
            type_len: parsed.type_len,
            interval_offset: parsed.interval_offset,
            interval_len: parsed.interval_len,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_dh_group_new(group_id: c_int) -> *mut c_void {
    dh_group_new(group_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_dh_group_from_params(
    generator: *const u8,
    generator_len: usize,
    modulus: *const u8,
    modulus_len: usize,
) -> *mut c_void {
    dh_group_from_params(generator, generator_len, modulus, modulus_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_dh_generate_key(group: *mut c_void, need_bits: usize) -> c_int {
    dh_generate_key(group, need_bits)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_dh_public_len(group: *const c_void) -> usize {
    dh_public_len(group)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_dh_export_public(
    group: *const c_void,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    dh_export_public(group, out, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_dh_modulus_len(group: *const c_void) -> usize {
    dh_modulus_len(group)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_dh_export_modulus(
    group: *const c_void,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    dh_export_modulus(group, out, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_dh_generator_len(group: *const c_void) -> usize {
    dh_generator_len(group)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_dh_export_generator(
    group: *const c_void,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    dh_export_generator(group, out, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_dh_shared_secret(
    group: *const c_void,
    peer_public: *const u8,
    peer_public_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    dh_shared_secret(group, peer_public, peer_public_len, out, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_dh_free(group: *mut c_void) {
    dh_free(group)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_digest_start(alg: c_int) -> *mut c_void {
    match DigestState::new(alg) {
        Some(state) => Box::into_raw(Box::new(state)).cast(),
        None => core::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_digest_copy(ctx: *const c_void) -> *mut c_void {
    if ctx.is_null() {
        return core::ptr::null_mut();
    }
    let ctx = unsafe { &*(ctx.cast::<DigestState>()) };
    Box::into_raw(Box::new(ctx.clone())).cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_digest_update(ctx: *mut c_void, data: *const u8, len: usize) -> c_int {
    if ctx.is_null() || (data.is_null() && len != 0) {
        return -1;
    }
    let ctx = unsafe { &mut *(ctx.cast::<DigestState>()) };
    let data = if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(data, len) }
    };
    ctx.update(data);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_digest_final(
    ctx: *const c_void,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if ctx.is_null() || out.is_null() {
        return -1;
    }
    let ctx = unsafe { &*(ctx.cast::<DigestState>()) };
    let out = if out_len == 0 {
        &mut []
    } else {
        unsafe { slice::from_raw_parts_mut(out, out_len) }
    };
    if ctx.finalize_to(out).is_err() {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_digest_free(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    let mut boxed = unsafe { Box::from_raw(ctx.cast::<DigestState>()) };
    boxed.scrub();
    drop(boxed);
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_hmac_start(alg: c_int) -> *mut c_void {
    match HmacState::new(alg) {
        Some(state) => Box::into_raw(Box::new(state)).cast(),
        None => core::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_hmac_init(ctx: *mut c_void, key: *const u8, key_len: usize) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *(ctx.cast::<HmacState>()) };
    if ctx.init(key, key_len).is_err() {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_hmac_update(
    ctx: *mut c_void,
    data: *const u8,
    data_len: usize,
) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *(ctx.cast::<HmacState>()) };
    if ctx.update(data, data_len).is_err() {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_hmac_final(ctx: *mut c_void, out: *mut u8, out_len: usize) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *(ctx.cast::<HmacState>()) };
    if ctx.finalise(out, out_len).is_err() {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_hmac_free(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    let mut boxed = unsafe { Box::from_raw(ctx.cast::<HmacState>()) };
    boxed.scrub();
    drop(boxed);
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_mac_start(alg: c_int, truncate_bits: c_int) -> *mut c_void {
    match PacketMacState::new(alg, truncate_bits) {
        Some(state) => Box::into_raw(Box::new(state)).cast(),
        None => core::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_mac_init(ctx: *mut c_void, key: *const u8, key_len: usize) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *(ctx.cast::<PacketMacState>()) };
    if ctx.init(key, key_len).is_err() {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_mac_compute(
    ctx: *mut c_void,
    seqno: u32,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *(ctx.cast::<PacketMacState>()) };
    if ctx.compute(seqno, data, data_len, out, out_len).is_err() {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_mac_check(
    ctx: *mut c_void,
    seqno: u32,
    data: *const u8,
    data_len: usize,
    their_mac: *const u8,
    their_mac_len: usize,
) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *(ctx.cast::<PacketMacState>()) };
    match ctx.check(seqno, data, data_len, their_mac, their_mac_len) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_mac_free(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    let mut boxed = unsafe { Box::from_raw(ctx.cast::<PacketMacState>()) };
    boxed.scrub();
    drop(boxed);
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ed25519_public_from_seed(
    seed: *const u8,
    seed_len: usize,
    public_key: *mut u8,
    public_key_len: usize,
) -> c_int {
    ed25519_public_from_seed(seed, seed_len, public_key, public_key_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ed25519_sign(
    sig: *mut u8,
    sig_len: usize,
    msg: *const u8,
    msg_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
) -> c_int {
    ed25519_sign(sig, sig_len, msg, msg_len, secret_key, secret_key_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ed25519_verify(
    sig: *const u8,
    sig_len: usize,
    msg: *const u8,
    msg_len: usize,
    public_key: *const u8,
    public_key_len: usize,
) -> c_int {
    ed25519_verify(sig, sig_len, msg, msg_len, public_key, public_key_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ed25519_parse_public_blob(
    blob: *const u8,
    blob_len: usize,
    public_key: *mut u8,
    public_key_len: usize,
    consumed_len: *mut usize,
) -> c_int {
    ed25519_parse_public_blob(blob, blob_len, public_key, public_key_len, consumed_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_curve25519_public_from_secret(
    public_key: *mut u8,
    public_key_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
) -> c_int {
    curve25519_public_from_secret(public_key, public_key_len, secret_key, secret_key_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_curve25519_shared_secret(
    shared_secret: *mut u8,
    shared_secret_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    public_key: *const u8,
    public_key_len: usize,
) -> c_int {
    curve25519_shared_secret(
        shared_secret,
        shared_secret_len,
        secret_key,
        secret_key_len,
        public_key,
        public_key_len,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_mlkem768x25519_keypair(
    client_blob: *mut u8,
    client_blob_len: usize,
    mlkem_secret: *mut u8,
    mlkem_secret_len: usize,
    curve25519_secret: *mut u8,
    curve25519_secret_len: usize,
) -> c_int {
    mlkem768x25519_keypair(
        client_blob,
        client_blob_len,
        mlkem_secret,
        mlkem_secret_len,
        curve25519_secret,
        curve25519_secret_len,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_mlkem768x25519_enc(
    client_blob: *const u8,
    client_blob_len: usize,
    server_blob: *mut u8,
    server_blob_len: usize,
    shared_hash: *mut u8,
    shared_hash_len: usize,
) -> c_int {
    mlkem768x25519_enc(
        client_blob,
        client_blob_len,
        server_blob,
        server_blob_len,
        shared_hash,
        shared_hash_len,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_mlkem768x25519_dec(
    server_blob: *const u8,
    server_blob_len: usize,
    mlkem_secret: *const u8,
    mlkem_secret_len: usize,
    curve25519_secret: *const u8,
    curve25519_secret_len: usize,
    shared_hash: *mut u8,
    shared_hash_len: usize,
) -> c_int {
    mlkem768x25519_dec(
        server_blob,
        server_blob_len,
        mlkem_secret,
        mlkem_secret_len,
        curve25519_secret,
        curve25519_secret_len,
        shared_hash,
        shared_hash_len,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sntrup761x25519_keypair(
    client_blob: *mut u8,
    client_blob_len: usize,
    sntrup_secret: *mut u8,
    sntrup_secret_len: usize,
    curve25519_secret: *mut u8,
    curve25519_secret_len: usize,
) -> c_int {
    sntrup761x25519_keypair(
        client_blob,
        client_blob_len,
        sntrup_secret,
        sntrup_secret_len,
        curve25519_secret,
        curve25519_secret_len,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sntrup761x25519_enc(
    client_blob: *const u8,
    client_blob_len: usize,
    server_blob: *mut u8,
    server_blob_len: usize,
    shared_hash: *mut u8,
    shared_hash_len: usize,
) -> c_int {
    sntrup761x25519_enc(
        client_blob,
        client_blob_len,
        server_blob,
        server_blob_len,
        shared_hash,
        shared_hash_len,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_sntrup761x25519_dec(
    server_blob: *const u8,
    server_blob_len: usize,
    sntrup_secret: *const u8,
    sntrup_secret_len: usize,
    curve25519_secret: *const u8,
    curve25519_secret_len: usize,
    shared_hash: *mut u8,
    shared_hash_len: usize,
) -> c_int {
    sntrup761x25519_dec(
        server_blob,
        server_blob_len,
        sntrup_secret,
        sntrup_secret_len,
        curve25519_secret,
        curve25519_secret_len,
        shared_hash,
        shared_hash_len,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdh_keypair(
    curve_id: c_int,
    secret_key: *mut u8,
    secret_key_len: usize,
    public_key: *mut u8,
    public_key_len: usize,
) -> c_int {
    if secret_key.is_null() || public_key.is_null() {
        return -1;
    }
    let curve = match EcdhCurve::from_id(curve_id) {
        Some(curve) => curve,
        None => return -1,
    };
    if secret_key_len != curve.secret_len() || public_key_len != curve.public_len() {
        return -1;
    }
    let secret_key = unsafe { slice::from_raw_parts_mut(secret_key, secret_key_len) };
    let public_key = unsafe { slice::from_raw_parts_mut(public_key, public_key_len) };
    if curve.generate_keypair(secret_key, public_key).is_err() {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdh_shared_secret(
    curve_id: c_int,
    secret_key: *const u8,
    secret_key_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    shared_secret: *mut u8,
    shared_secret_len: usize,
) -> c_int {
    if secret_key.is_null() || public_key.is_null() || shared_secret.is_null() {
        return -1;
    }
    let curve = match EcdhCurve::from_id(curve_id) {
        Some(curve) => curve,
        None => return -1,
    };
    if secret_key_len != curve.secret_len()
        || public_key_len != curve.public_len()
        || shared_secret_len != curve.shared_len()
    {
        return -1;
    }
    let secret_key = unsafe { slice::from_raw_parts(secret_key, secret_key_len) };
    let public_key = unsafe { slice::from_raw_parts(public_key, public_key_len) };
    let shared_secret = unsafe { slice::from_raw_parts_mut(shared_secret, shared_secret_len) };
    if curve
        .shared_secret(secret_key, public_key, shared_secret)
        .is_err()
    {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_generate(curve_nid: c_int) -> *mut c_void {
    ecdsa_generate(curve_nid)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_parse_public_blob(
    curve_nid: c_int,
    blob: *const u8,
    blob_len: usize,
    consumed_len: *mut usize,
    parse_status: *mut c_int,
) -> *mut c_void {
    match ecdsa_parse_public_blob(curve_nid, blob, blob_len, consumed_len) {
        Ok(key) => {
            store_parse_status(parse_status, OSSH_RUST_ECDSA_PARSE_OK);
            key
        }
        Err(status) => {
            let status = match status {
                OSSH_RUST_ECDSA_PARSE_OK => OSSH_RUST_PARSE_STATUS_OK,
                OSSH_RUST_ECDSA_PARSE_CURVE_MISMATCH => {
                    OSSH_RUST_PARSE_STATUS_EC_CURVE_MISMATCH
                }
                OSSH_RUST_ECDSA_PARSE_INVALID_FORMAT => OSSH_RUST_PARSE_STATUS_INVALID_FORMAT,
                _ => OSSH_RUST_PARSE_STATUS_INVALID_FORMAT,
            };
            store_parse_status(parse_status, status);
            core::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_from_public(
    curve_nid: c_int,
    public_key: *const u8,
    public_key_len: usize,
) -> *mut c_void {
    ecdsa_from_public(curve_nid, public_key, public_key_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_from_private(
    curve_nid: c_int,
    public_key: *const u8,
    public_key_len: usize,
    private_key: *const u8,
    private_key_len: usize,
) -> *mut c_void {
    ecdsa_from_private(curve_nid, public_key, public_key_len, private_key, private_key_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_copy_public(key: *const c_void) -> *mut c_void {
    ecdsa_copy_public(key)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_equal_public(a: *const c_void, b: *const c_void) -> c_int {
    ecdsa_equal_public(a, b)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_export_public(
    key: *const c_void,
    public_key: *mut u8,
    public_key_len: usize,
) -> c_int {
    ecdsa_export_public(key, public_key, public_key_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_export_private(
    key: *const c_void,
    private_key: *mut u8,
    private_key_len: usize,
) -> c_int {
    ecdsa_export_private(key, private_key, private_key_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_curve_nid(key: *const c_void) -> c_int {
    ecdsa_curve_nid(key)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_parse_private_pem(
    blob: *const u8,
    blob_len: usize,
) -> *mut c_void {
    ecdsa_parse_private_pem(blob, blob_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_parse_private_pem_passphrase(
    blob: *const u8,
    blob_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    status: *mut c_int,
) -> *mut c_void {
    store_parse_status(status, OSSH_RUST_PARSE_STATUS_INVALID_FORMAT);
    match ecdsa_parse_private_pem_with_passphrase(blob, blob_len, passphrase, passphrase_len) {
        Ok(key) => {
            store_parse_status(status, OSSH_RUST_PARSE_STATUS_OK);
            key
        }
        Err(err) => {
            store_parse_status(status, parse_status(err));
            core::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_private_pem_len(key: *const c_void, format: c_int) -> usize {
    ecdsa_private_pem_len(key, format)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_private_pem_write(
    key: *const c_void,
    format: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    ecdsa_private_pem_write(key, format, out, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_sign_prehashed(
    key: *const c_void,
    digest: *const u8,
    digest_len: usize,
    signature: *mut u8,
    signature_len: usize,
) -> c_int {
    ecdsa_sign_prehashed(key, digest, digest_len, signature, signature_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_verify_prehashed(
    key: *const c_void,
    digest: *const u8,
    digest_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    ecdsa_verify_prehashed(key, digest, digest_len, signature, signature_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdsa_free(key: *mut c_void) {
    ecdsa_free(key)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_generate(bits: usize) -> *mut c_void {
    rsa_generate(bits)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_parse_public_blob(
    blob: *const u8,
    blob_len: usize,
    consumed_len: *mut usize,
) -> *mut c_void {
    rsa_parse_public_blob(blob, blob_len, consumed_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_from_public(
    modulus: *const u8,
    modulus_len: usize,
    exponent: *const u8,
    exponent_len: usize,
) -> *mut c_void {
    rsa_from_public(modulus, modulus_len, exponent, exponent_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_from_private(
    modulus: *const u8,
    modulus_len: usize,
    exponent: *const u8,
    exponent_len: usize,
    private_exponent: *const u8,
    private_exponent_len: usize,
    iqmp: *const u8,
    iqmp_len: usize,
    prime_p: *const u8,
    prime_p_len: usize,
    prime_q: *const u8,
    prime_q_len: usize,
) -> *mut c_void {
    rsa_from_private(
        modulus,
        modulus_len,
        exponent,
        exponent_len,
        private_exponent,
        private_exponent_len,
        iqmp,
        iqmp_len,
        prime_p,
        prime_p_len,
        prime_q,
        prime_q_len,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_copy_public(key: *const c_void) -> *mut c_void {
    rsa_copy_public(key)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_equal_public(a: *const c_void, b: *const c_void) -> c_int {
    rsa_equal_public(a, b)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_bits(key: *const c_void) -> usize {
    rsa_bits(key)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_component_len(key: *const c_void, component: c_int) -> usize {
    rsa_component_len(key, component)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_export_component(
    key: *const c_void,
    component: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    rsa_export_component(key, component, out, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_parse_private_pem(
    blob: *const u8,
    blob_len: usize,
) -> *mut c_void {
    rsa_parse_private_pem(blob, blob_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_parse_private_pem_passphrase(
    blob: *const u8,
    blob_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    status: *mut c_int,
) -> *mut c_void {
    store_parse_status(status, OSSH_RUST_PARSE_STATUS_INVALID_FORMAT);
    match rsa_parse_private_pem_with_passphrase(blob, blob_len, passphrase, passphrase_len) {
        Ok(key) => {
            store_parse_status(status, OSSH_RUST_PARSE_STATUS_OK);
            key
        }
        Err(err) => {
            store_parse_status(status, parse_status(err));
            core::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_private_pem_len(key: *const c_void, format: c_int) -> usize {
    rsa_private_pem_len(key, format)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_private_pem_write(
    key: *const c_void,
    format: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    rsa_private_pem_write(key, format, out, out_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_write_prefix(out: *mut u8, out_len: usize, src: *const u8, src_len: usize) -> c_int {
    let Some(src) = read_slice(src, src_len) else {
        return -1;
    };
    write_prefix(out, out_len, src)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_sign_prehashed(
    key: *const c_void,
    hash_alg: c_int,
    digest: *const u8,
    digest_len: usize,
    signature: *mut u8,
    signature_len: usize,
) -> c_int {
    rsa_sign_prehashed(key, hash_alg, digest, digest_len, signature, signature_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_verify_prehashed(
    key: *const c_void,
    hash_alg: c_int,
    digest: *const u8,
    digest_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    rsa_verify_prehashed(key, hash_alg, digest, digest_len, signature, signature_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_rsa_free(key: *mut c_void) {
    rsa_free(key)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_aesctr_init(
    key: *const u8,
    key_len: usize,
    iv: *const u8,
    iv_len: usize,
) -> *mut c_void {
    aesctr_init(key, key_len, iv, iv_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_aesctr_set_iv(ctx: *mut c_void, iv: *const u8, iv_len: usize) -> c_int {
    aesctr_set_iv(ctx, iv, iv_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_aesctr_get_iv(ctx: *const c_void, iv: *mut u8, iv_len: usize) -> c_int {
    aesctr_get_iv(ctx, iv, iv_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_aesctr_crypt(
    ctx: *mut c_void,
    src: *const u8,
    dst: *mut u8,
    len: usize,
) -> c_int {
    aesctr_crypt(ctx, src, dst, len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_aesctr_free(ctx: *mut c_void) {
    aesctr_free(ctx)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_chachapoly_new(key: *const u8, key_len: usize) -> *mut c_void {
    chachapoly_new(key, key_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_chachapoly_crypt(
    ctx: *mut c_void,
    seqnr: u32,
    dest: *mut u8,
    dest_len: usize,
    src: *const u8,
    src_len: usize,
    len: u32,
    aadlen: u32,
    authlen: u32,
    do_encrypt: c_int,
) -> c_int {
    chachapoly_crypt(
        ctx,
        seqnr,
        dest,
        dest_len,
        src,
        src_len,
        len,
        aadlen,
        authlen,
        do_encrypt,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_chachapoly_get_length(
    ctx: *mut c_void,
    plenp: *mut u32,
    seqnr: u32,
    cp: *const u8,
    len: usize,
) -> c_int {
    chachapoly_get_length(ctx, plenp, seqnr, cp, len)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_chachapoly_free(ctx: *mut c_void) {
    chachapoly_free(ctx)
}
