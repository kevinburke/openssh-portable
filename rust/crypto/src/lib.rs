mod cert;
mod cipher;
mod dh;
mod digest;
mod ecdsa;
mod kex;
mod openssh_key;
mod private_pem;
mod rsa;
mod util;

use core::ffi::{c_char, c_int, c_void};
use core::slice;

use cert::parse_cert_body;
use cipher::{
    aesctr_crypt, aesctr_free, aesctr_get_iv, aesctr_init, aesctr_set_iv,
    chachapoly_crypt, chachapoly_free, chachapoly_get_length, chachapoly_new,
};
use dh::{dh_export_public, dh_free, dh_generate_key, dh_group_new, dh_public_len, dh_shared_secret};
use digest::DigestState;
use ecdsa::{
    ecdsa_copy_public, ecdsa_equal_public, ecdsa_export_private, ecdsa_export_public,
    ecdsa_free, ecdsa_from_private, ecdsa_from_public, ecdsa_generate, ecdsa_curve_nid,
    ecdsa_parse_private_pem, ecdsa_parse_private_pem_with_passphrase, ecdsa_parse_public_blob, ecdsa_private_pem_len,
    ecdsa_private_pem_write, ecdsa_sign_prehashed, ecdsa_verify_prehashed,
};
use kex::{
    curve25519_public_from_secret, curve25519_shared_secret, ed25519_parse_public_blob,
    ed25519_public_from_seed, ed25519_sign, ed25519_verify, EcdhCurve,
};
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
use util::{argv_split_parse, argv_split_write, read_slice, write_prefix};

const OSSH_RUST_CRYPTO_ABI_VERSION: u32 = 15;
const OSSH_RUST_PARSE_STATUS_OK: c_int = 0;
const OSSH_RUST_PARSE_STATUS_INVALID_FORMAT: c_int = 1;
const OSSH_RUST_PARSE_STATUS_WRONG_PASSPHRASE: c_int = 2;
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
pub extern "C" fn ossh_rust_dh_group_new(group_id: c_int) -> *mut c_void {
    dh_group_new(group_id)
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
) -> *mut c_void {
    ecdsa_parse_public_blob(curve_nid, blob, blob_len, consumed_len)
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
