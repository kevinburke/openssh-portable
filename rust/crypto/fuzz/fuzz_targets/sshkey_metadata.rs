#![no_main]

use core::ffi::{c_char, c_int, c_void};

use libfuzzer_sys::fuzz_target;
use rust_crypto::{
    ossh_rust_sshkey_ecdsa_nid_from_name, ossh_rust_sshkey_impl_name_from_type_nid,
    ossh_rust_sshkey_type_from_name, ossh_rust_sshkey_type_is_valid_ca, RustSshkeyImplEntry,
};

const KEY_RSA: c_int = 0;
const KEY_ECDSA: c_int = 1;
const KEY_ED25519: c_int = 2;
const KEY_RSA_CERT: c_int = 3;

const SSH_ED25519: &[u8] = b"ssh-ed25519\0";
const ECDSA_P256: &[u8] = b"ecdsa-sha2-nistp256\0";
const ECDSA_P384: &[u8] = b"ecdsa-sha2-nistp384\0";
const SSH_RSA: &[u8] = b"ssh-rsa\0";
const RSA_SHA256: &[u8] = b"rsa-sha2-256\0";
const SSH_RSA_CERT: &[u8] = b"ssh-rsa-cert-v01@openssh.com\0";
const SHORT_ED25519: &[u8] = b"ED25519\0";
const SHORT_ECDSA: &[u8] = b"ECDSA\0";
const SHORT_RSA: &[u8] = b"RSA\0";
const SHORT_RSA_CERT: &[u8] = b"RSA-CERT\0";

// These exported helpers read C string metadata, so the fixture strings need
// explicit trailing NUL bytes rather than plain Rust byte slices.
const ENTRIES: [RustSshkeyImplEntry; 6] = [
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
        name: ECDSA_P384.as_ptr().cast(),
        shortname: SHORT_ECDSA.as_ptr().cast(),
        sigalg: core::ptr::null(),
        type_: KEY_ECDSA,
        nid: 715,
        cert: 0,
        sigonly: 0,
        keybits: 384,
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
    RustSshkeyImplEntry {
        name: RSA_SHA256.as_ptr().cast(),
        shortname: SHORT_RSA.as_ptr().cast(),
        sigalg: core::ptr::null(),
        type_: KEY_RSA,
        nid: 0,
        cert: 0,
        sigonly: 1,
        keybits: 0,
        funcs: core::ptr::null::<c_void>(),
    },
];

fn entry_ptrs() -> [*const RustSshkeyImplEntry; ENTRIES.len()] {
    core::array::from_fn(|idx| &ENTRIES[idx] as *const RustSshkeyImplEntry)
}

fuzz_target!(|data: &[u8]| {
    let entries = entry_ptrs();
    let mut parsed_type = -1;
    let mut parsed_nid = -1;
    let mut ca_ok = -1;
    let mut out_name: *const c_char = core::ptr::null();

    let allow_short = i32::from(data.len() % 2 == 0);
    let _ = ossh_rust_sshkey_type_from_name(
        data.as_ptr(),
        data.len(),
        entries.as_ptr(),
        entries.len(),
        allow_short,
        &mut parsed_type,
    );
    let _ = ossh_rust_sshkey_ecdsa_nid_from_name(
        data.as_ptr(),
        data.len(),
        entries.as_ptr(),
        entries.len(),
        &mut parsed_nid,
    );
    let _ = ossh_rust_sshkey_type_is_valid_ca(KEY_RSA_CERT, entries.as_ptr(), entries.len(), &mut ca_ok);
    let _ = ossh_rust_sshkey_impl_name_from_type_nid(
        KEY_ECDSA,
        if data.len() % 3 == 0 { 715 } else { 415 },
        0,
        entries.as_ptr(),
        entries.len(),
        &mut out_name,
    );

    let _ = parsed_type;
    let _ = parsed_nid;
    let _ = ca_ok;
    let _ = out_name;
});
