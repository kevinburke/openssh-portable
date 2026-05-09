#![no_main]

use core::{ffi::{c_int, c_void}, mem};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rust_crypto::{
    ossh_rust_private2_decode_len, ossh_rust_private2_decode_write,
    ossh_rust_private2_parse_header, ossh_rust_private2_parse_plaintext,
    ossh_rust_public_blob_decode_len, ossh_rust_public_blob_decode_write,
    ossh_rust_public_line_parse,
    ossh_rust_sshkey_equal_plan, ossh_rust_sshkey_equal_public_plan,
    ossh_rust_sshkey_free_contents_plan, ossh_rust_sshkey_from_blob_plan,
    ossh_rust_sshkey_from_private_plan, ossh_rust_sshkey_generate_plan,
    ossh_rust_sshkey_private_deserialize_plan, ossh_rust_sshkey_private_serialize_plan,
    ossh_rust_sshkey_serialize_plan, ossh_rust_sshkey_new_plan, ossh_rust_sshkey_type_from_name,
    ossh_rust_sshkey_type_is_cert, ossh_rust_sshkey_type_plain, RustPrivate2HeaderParse,
    RustPrivate2PlaintextParse, RustPublicLineParse, RustSshkeyImplEntry,
};

const KEY_RSA: c_int = 0;
const KEY_ECDSA: c_int = 1;
const KEY_ED25519: c_int = 2;
const KEY_RSA_CERT: c_int = 3;
const KEY_ECDSA_CERT: c_int = 4;
const KEY_ED25519_CERT: c_int = 5;
const KEY_ECDSA_SK: c_int = 6;
const KEY_ECDSA_SK_CERT: c_int = 7;
const KEY_ED25519_SK: c_int = 8;
const KEY_ED25519_SK_CERT: c_int = 9;
const KEY_UNSPEC: c_int = 10;

const SSH_ED25519: &[u8] = b"ssh-ed25519\0";
const SSH_ED25519_CERT: &[u8] = b"ssh-ed25519-cert-v01@openssh.com\0";
const ECDSA_P256: &[u8] = b"ecdsa-sha2-nistp256\0";
const ECDSA_P256_CERT: &[u8] = b"ecdsa-sha2-nistp256-cert-v01@openssh.com\0";
const SK_ECDSA_P256: &[u8] = b"sk-ecdsa-sha2-nistp256@openssh.com\0";
const SK_ECDSA_P256_CERT: &[u8] = b"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com\0";
const SSH_RSA: &[u8] = b"ssh-rsa\0";
const SSH_RSA_CERT: &[u8] = b"ssh-rsa-cert-v01@openssh.com\0";
const SHORT_ED25519: &[u8] = b"ED25519\0";
const SHORT_ED25519_CERT: &[u8] = b"ED25519-CERT\0";
const SHORT_ECDSA: &[u8] = b"ECDSA\0";
const SHORT_ECDSA_CERT: &[u8] = b"ECDSA-CERT\0";
const SHORT_RSA: &[u8] = b"RSA\0";
const SHORT_RSA_CERT: &[u8] = b"RSA-CERT\0";

const ENTRIES: [RustSshkeyImplEntry; 8] = [
    RustSshkeyImplEntry {
        name: SSH_ED25519.as_ptr().cast(),
        shortname: SHORT_ED25519.as_ptr().cast(),
        sigalg: core::ptr::null(),
        type_: KEY_ED25519,
        nid: 0,
        cert: 0,
        sigonly: 0,
        keybits: 256,
        funcs: core::ptr::null::<c_void>(),
    },
    RustSshkeyImplEntry {
        name: SSH_ED25519_CERT.as_ptr().cast(),
        shortname: SHORT_ED25519_CERT.as_ptr().cast(),
        sigalg: core::ptr::null(),
        type_: KEY_ED25519_CERT,
        nid: 0,
        cert: 1,
        sigonly: 0,
        keybits: 256,
        funcs: core::ptr::null::<c_void>(),
    },
    RustSshkeyImplEntry {
        name: ECDSA_P256.as_ptr().cast(),
        shortname: SHORT_ECDSA.as_ptr().cast(),
        sigalg: core::ptr::null(),
        type_: KEY_ECDSA,
        nid: 415,
        cert: 0,
        sigonly: 0,
        keybits: 256,
        funcs: core::ptr::null::<c_void>(),
    },
    RustSshkeyImplEntry {
        name: ECDSA_P256_CERT.as_ptr().cast(),
        shortname: SHORT_ECDSA_CERT.as_ptr().cast(),
        sigalg: core::ptr::null(),
        type_: KEY_ECDSA_CERT,
        nid: 415,
        cert: 1,
        sigonly: 0,
        keybits: 256,
        funcs: core::ptr::null::<c_void>(),
    },
    RustSshkeyImplEntry {
        name: SK_ECDSA_P256.as_ptr().cast(),
        shortname: SHORT_ECDSA.as_ptr().cast(),
        sigalg: core::ptr::null(),
        type_: KEY_ECDSA_SK,
        nid: 415,
        cert: 0,
        sigonly: 0,
        keybits: 256,
        funcs: core::ptr::null::<c_void>(),
    },
    RustSshkeyImplEntry {
        name: SK_ECDSA_P256_CERT.as_ptr().cast(),
        shortname: SHORT_ECDSA_CERT.as_ptr().cast(),
        sigalg: core::ptr::null(),
        type_: KEY_ECDSA_SK_CERT,
        nid: 415,
        cert: 1,
        sigonly: 0,
        keybits: 256,
        funcs: core::ptr::null::<c_void>(),
    },
    RustSshkeyImplEntry {
        name: SSH_RSA.as_ptr().cast(),
        shortname: SHORT_RSA.as_ptr().cast(),
        sigalg: core::ptr::null(),
        type_: KEY_RSA,
        nid: 0,
        cert: 0,
        sigonly: 0,
        keybits: 0,
        funcs: core::ptr::null::<c_void>(),
    },
    RustSshkeyImplEntry {
        name: SSH_RSA_CERT.as_ptr().cast(),
        shortname: SHORT_RSA_CERT.as_ptr().cast(),
        sigalg: core::ptr::null(),
        type_: KEY_RSA_CERT,
        nid: 0,
        cert: 1,
        sigonly: 0,
        keybits: 0,
        funcs: core::ptr::null::<c_void>(),
    },
];

const CANDIDATE_TYPES: [c_int; 11] = [
    KEY_RSA,
    KEY_ECDSA,
    KEY_ED25519,
    KEY_RSA_CERT,
    KEY_ECDSA_CERT,
    KEY_ED25519_CERT,
    KEY_ECDSA_SK,
    KEY_ECDSA_SK_CERT,
    KEY_ED25519_SK,
    KEY_ED25519_SK_CERT,
    4242,
];

fn entry_ptrs() -> [*const RustSshkeyImplEntry; ENTRIES.len()] {
    core::array::from_fn(|idx| &ENTRIES[idx] as *const RustSshkeyImplEntry)
}

#[derive(Arbitrary, Debug)]
struct Input {
    name: Vec<u8>,
    alt_name: Vec<u8>,
    public_line: Vec<u8>,
    armored_private: Vec<u8>,
    plaintext_private: Vec<u8>,
    bits: u8,
    certblob_len: u16,
    flags: u8,
    lhs_idx: u8,
    rhs_idx: u8,
    nid_hint: u16,
}

fn pick_type(idx: u8) -> c_int {
    CANDIDATE_TYPES[idx as usize % CANDIDATE_TYPES.len()]
}

fuzz_target!(|input: Input| {
    let entries = entry_ptrs();
    let lhs_type = pick_type(input.lhs_idx);
    let rhs_type = pick_type(input.rhs_idx);
    let certblob_len = usize::from(input.certblob_len);
    let nid_hint = i32::from(input.nid_hint);
    let allow_short = i32::from(input.flags & 1 != 0);
    let allow_cert = i32::from(input.flags & 2 != 0);
    let has_cert = i32::from(input.flags & 4 != 0);
    let force_plain = i32::from(input.flags & 8 != 0);

    let mut out_type = KEY_UNSPEC;
    let mut out_bool = 0;
    let mut out_impl_index = KEY_UNSPEC;
    let mut out_dispatch_type = KEY_UNSPEC;
    let mut out_expected_cert_nid = -1;
    let mut out_use_noec_fallback = 0;
    let mut out_name_type = KEY_UNSPEC;
    let mut public_line: RustPublicLineParse = unsafe { mem::zeroed() };
    let mut private2_header: RustPrivate2HeaderParse = unsafe { mem::zeroed() };
    let mut private2_plaintext: RustPrivate2PlaintextParse = unsafe { mem::zeroed() };

    let _ = ossh_rust_sshkey_type_from_name(
        input.name.as_ptr(),
        input.name.len(),
        entries.as_ptr(),
        entries.len(),
        allow_short,
        &mut out_name_type,
    );
    let _ = ossh_rust_sshkey_type_is_cert(lhs_type, &mut out_bool);
    let _ = ossh_rust_sshkey_type_plain(lhs_type, &mut out_type);
    let _ = ossh_rust_sshkey_new_plan(
        lhs_type,
        entries.as_ptr(),
        entries.len(),
        &mut out_bool,
        &mut out_impl_index,
        &mut out_dispatch_type,
    );
    let _ = ossh_rust_sshkey_generate_plan(lhs_type, entries.as_ptr(), entries.len(), &mut out_type);
    let _ = ossh_rust_sshkey_serialize_plan(
        lhs_type,
        force_plain,
        has_cert,
        certblob_len,
        &mut out_type,
        &mut out_bool,
    );
    let _ = ossh_rust_sshkey_from_private_plan(
        lhs_type,
        nid_hint,
        entries.as_ptr(),
        entries.len(),
        &mut out_type,
        &mut out_bool,
    );
    let _ = ossh_rust_sshkey_equal_public_plan(
        lhs_type,
        rhs_type,
        entries.as_ptr(),
        entries.len(),
        &mut out_bool,
        &mut out_dispatch_type,
    );
    let _ = ossh_rust_sshkey_equal_plan(
        lhs_type,
        rhs_type,
        entries.as_ptr(),
        entries.len(),
        &mut out_bool,
        &mut out_dispatch_type,
    );
    let _ = ossh_rust_sshkey_from_blob_plan(
        input.name.as_ptr(),
        input.name.len(),
        allow_cert,
        entries.as_ptr(),
        entries.len(),
        &mut out_type,
        &mut out_impl_index,
        &mut out_use_noec_fallback,
    );
    let _ = ossh_rust_sshkey_private_deserialize_plan(
        input.alt_name.as_ptr(),
        input.alt_name.len(),
        entries.as_ptr(),
        entries.len(),
        &mut out_type,
        &mut out_bool,
        &mut out_impl_index,
        &mut out_expected_cert_nid,
    );
    let _ = ossh_rust_sshkey_private_serialize_plan(
        lhs_type,
        nid_hint,
        has_cert,
        certblob_len,
        entries.as_ptr(),
        entries.len(),
        &mut out_impl_index,
    );
    let _ = ossh_rust_sshkey_free_contents_plan(
        rhs_type,
        entries.as_ptr(),
        entries.len(),
        &mut out_bool,
        &mut out_impl_index,
    );
    let _ = ossh_rust_public_line_parse(
        input.public_line.as_ptr(),
        input.public_line.len(),
        &mut public_line,
    );
    let public_blob_len =
        ossh_rust_public_blob_decode_len(input.public_line.as_ptr(), input.public_line.len());
    if public_blob_len > 0 && public_blob_len <= 1 << 20 {
        let mut decoded = vec![0u8; public_blob_len];
        let _ = ossh_rust_public_blob_decode_write(
            input.public_line.as_ptr(),
            input.public_line.len(),
            decoded.as_mut_ptr(),
            decoded.len(),
        );
    }
    let private2_len =
        ossh_rust_private2_decode_len(input.armored_private.as_ptr(), input.armored_private.len());
    if private2_len > 0 && private2_len <= 1 << 20 {
        let mut decoded = vec![0u8; private2_len];
        if ossh_rust_private2_decode_write(
            input.armored_private.as_ptr(),
            input.armored_private.len(),
            decoded.as_mut_ptr(),
            decoded.len(),
        ) == 0
        {
            let _ = ossh_rust_private2_parse_header(
                decoded.as_ptr(),
                decoded.len(),
                &mut private2_header,
            );
        }
    }
    let _ = ossh_rust_private2_parse_plaintext(
        input.plaintext_private.as_ptr(),
        input.plaintext_private.len(),
        &mut private2_plaintext,
    );

    let _ = input.bits;
});
