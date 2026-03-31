use core::ffi::{c_char, c_int, c_void, CStr};
use core::slice;

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
const SSH_ERR_EXPECTED_CERT: c_int = -16;
const SSH_ERR_KEY_LACKS_CERTBLOB: c_int = -17;

#[repr(C)]
pub struct RustSshkeyImpl {
    pub name: *const c_char,
    pub shortname: *const c_char,
    pub sigalg: *const c_char,
    pub type_: c_int,
    pub nid: c_int,
    pub cert: c_int,
    pub sigonly: c_int,
    pub keybits: c_int,
    pub funcs: *const c_void,
}

fn read_input<'a>(input: *const u8, input_len: usize) -> Option<&'a [u8]> {
    if input.is_null() && input_len != 0 {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(input, input_len) })
}

fn keyimpls<'a>(
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Option<&'a [*const RustSshkeyImpl]> {
    if entries.is_null() && nentries != 0 {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(entries, nentries) })
}

fn entry_bytes(ptr: *const c_char) -> Option<&'static [u8]> {
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { CStr::from_ptr(ptr).to_bytes() })
}

fn entry_ref<'a>(ptr: *const RustSshkeyImpl) -> Option<&'a RustSshkeyImpl> {
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { &*ptr })
}

fn matches_type_nid(entry: &RustSshkeyImpl, type_: c_int, nid: c_int) -> bool {
    entry.type_ == type_ && (entry.nid == 0 || entry.nid == nid)
}

fn is_ecdsa_variant(type_: c_int) -> bool {
    matches!(type_, KEY_ECDSA | KEY_ECDSA_CERT | KEY_ECDSA_SK | KEY_ECDSA_SK_CERT)
}

pub(crate) fn sshkey_type_is_cert(type_: c_int) -> bool {
    matches!(
        type_,
        KEY_RSA_CERT | KEY_ECDSA_CERT | KEY_ECDSA_SK_CERT | KEY_ED25519_CERT | KEY_ED25519_SK_CERT
    )
}

pub(crate) fn sshkey_type_plain(type_: c_int) -> c_int {
    match type_ {
        KEY_RSA_CERT => KEY_RSA,
        KEY_ECDSA_CERT => KEY_ECDSA,
        KEY_ECDSA_SK_CERT => KEY_ECDSA_SK,
        KEY_ED25519_CERT => KEY_ED25519,
        KEY_ED25519_SK_CERT => KEY_ED25519_SK,
        _ => type_,
    }
}

pub(crate) fn sshkey_type_certified(type_: c_int) -> Option<c_int> {
    match type_ {
        KEY_RSA => Some(KEY_RSA_CERT),
        KEY_ECDSA => Some(KEY_ECDSA_CERT),
        KEY_ECDSA_SK => Some(KEY_ECDSA_SK_CERT),
        KEY_ED25519 => Some(KEY_ED25519_CERT),
        KEY_ED25519_SK => Some(KEY_ED25519_SK_CERT),
        _ => None,
    }
}

pub(crate) fn sshkey_type_is_sk(type_: c_int) -> bool {
    matches!(sshkey_type_plain(type_), KEY_ECDSA_SK | KEY_ED25519_SK)
}

pub(crate) fn sshkey_type_can_new(
    type_: c_int,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Option<bool> {
    if type_ == KEY_UNSPEC {
        return Some(true);
    }
    if sshkey_impl_index_from_type(type_, entries, nentries).is_some() {
        return Some(true);
    }
    Some(is_ecdsa_variant(type_) && sshkey_type_plain(type_) == KEY_ECDSA)
}

pub(crate) fn sshkey_serialize_plan(
    type_: c_int,
    force_plain: bool,
    has_cert: bool,
    certblob_len: usize,
) -> Result<(c_int, bool), c_int> {
    let effective_type = if force_plain {
        sshkey_type_plain(type_)
    } else {
        type_
    };

    if sshkey_type_is_cert(effective_type) {
        if !has_cert {
            return Err(SSH_ERR_EXPECTED_CERT);
        }
        if certblob_len == 0 {
            return Err(SSH_ERR_KEY_LACKS_CERTBLOB);
        }
        return Ok((effective_type, true));
    }
    Ok((effective_type, false))
}

pub(crate) fn sshkey_type_from_name(
    input: *const u8,
    input_len: usize,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
    allow_short: bool,
) -> Option<c_int> {
    let input = read_input(input, input_len)?;
    let entries = keyimpls(entries, nentries)?;

    for entry_ptr in entries {
        let entry = entry_ref(*entry_ptr)?;
        if let Some(name) = entry_bytes(entry.name) {
            if name == input {
                return Some(entry.type_);
            }
        }
        if allow_short && entry.cert == 0 {
            if let Some(shortname) = entry_bytes(entry.shortname) {
                if shortname.eq_ignore_ascii_case(input) {
                    return Some(entry.type_);
                }
            }
        }
    }
    None
}

pub(crate) fn sshkey_impl_name_from_type_nid(
    type_: c_int,
    nid: c_int,
    want_short: bool,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Option<*const c_char> {
    let entries = keyimpls(entries, nentries)?;

    for entry_ptr in entries {
        let entry = entry_ref(*entry_ptr)?;
        if matches_type_nid(entry, type_, nid) {
            let name = if want_short { entry.shortname } else { entry.name };
            if !name.is_null() {
                return Some(name);
            }
        }
    }
    None
}

pub(crate) fn sshkey_impl_index_from_type(
    type_: c_int,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Option<usize> {
    let entries = keyimpls(entries, nentries)?;

    for (idx, entry_ptr) in entries.iter().enumerate() {
        let entry = entry_ref(*entry_ptr)?;
        if entry.type_ == type_ {
            return Some(idx);
        }
    }
    None
}

pub(crate) fn sshkey_impl_index_from_type_nid(
    type_: c_int,
    nid: c_int,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Option<usize> {
    let entries = keyimpls(entries, nentries)?;

    for (idx, entry_ptr) in entries.iter().enumerate() {
        let entry = entry_ref(*entry_ptr)?;
        if matches_type_nid(entry, type_, nid) {
            return Some(idx);
        }
    }
    None
}

pub(crate) fn sshkey_ecdsa_nid_from_name(
    input: *const u8,
    input_len: usize,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Option<c_int> {
    let input = read_input(input, input_len)?;
    let entries = keyimpls(entries, nentries)?;

    for entry_ptr in entries {
        let entry = entry_ref(*entry_ptr)?;
        if !is_ecdsa_variant(entry.type_) {
            continue;
        }
        if let Some(name) = entry_bytes(entry.name) {
            if name == input {
                return Some(entry.nid);
            }
        }
    }
    None
}

pub(crate) fn sshkey_type_is_valid_ca(
    type_: c_int,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Option<bool> {
    if type_ == KEY_ECDSA {
        return Some(true);
    }
    let entries = keyimpls(entries, nentries)?;

    for entry_ptr in entries {
        let entry = entry_ref(*entry_ptr)?;
        if entry.type_ == type_ {
            return Some(entry.cert == 0);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    const SSH_ED25519: &[u8] = b"ssh-ed25519\0";
    const SSH_ED25519_CERT: &[u8] = b"ssh-ed25519-cert-v01@openssh.com\0";
    const ECDSA_P256: &[u8] = b"ecdsa-sha2-nistp256\0";
    const ECDSA_P384: &[u8] = b"ecdsa-sha2-nistp384\0";
    const ECDSA_P256_CERT: &[u8] = b"ecdsa-sha2-nistp256-cert-v01@openssh.com\0";
    const SSH_RSA: &[u8] = b"ssh-rsa\0";
    const RSA_SHA256: &[u8] = b"rsa-sha2-256\0";
    const SSH_RSA_CERT: &[u8] = b"ssh-rsa-cert-v01@openssh.com\0";
    const SHORT_ED25519: &[u8] = b"ED25519\0";
    const SHORT_ED25519_CERT: &[u8] = b"ED25519-CERT\0";
    const SHORT_ECDSA: &[u8] = b"ECDSA\0";
    const SHORT_ECDSA_CERT: &[u8] = b"ECDSA-CERT\0";
    const SHORT_RSA: &[u8] = b"RSA\0";
    const SHORT_RSA_CERT: &[u8] = b"RSA-CERT\0";

    const ENTRIES: [RustSshkeyImpl; 8] = [
        RustSshkeyImpl {
            name: SSH_ED25519.as_ptr().cast(),
            shortname: SHORT_ED25519.as_ptr().cast(),
            sigalg: core::ptr::null(),
            type_: KEY_ED25519,
            nid: 0,
            cert: 0,
            sigonly: 0,
            keybits: 256,
            funcs: core::ptr::null(),
        },
        RustSshkeyImpl {
            name: SSH_ED25519_CERT.as_ptr().cast(),
            shortname: SHORT_ED25519_CERT.as_ptr().cast(),
            sigalg: core::ptr::null(),
            type_: KEY_ED25519_CERT,
            nid: 0,
            cert: 1,
            sigonly: 0,
            keybits: 256,
            funcs: core::ptr::null(),
        },
        RustSshkeyImpl {
            name: ECDSA_P256.as_ptr().cast(),
            shortname: SHORT_ECDSA.as_ptr().cast(),
            sigalg: core::ptr::null(),
            type_: KEY_ECDSA,
            nid: 415,
            cert: 0,
            sigonly: 0,
            keybits: 256,
            funcs: core::ptr::null(),
        },
        RustSshkeyImpl {
            name: ECDSA_P256_CERT.as_ptr().cast(),
            shortname: SHORT_ECDSA_CERT.as_ptr().cast(),
            sigalg: core::ptr::null(),
            type_: KEY_ECDSA_CERT,
            nid: 415,
            cert: 1,
            sigonly: 0,
            keybits: 256,
            funcs: core::ptr::null(),
        },
        RustSshkeyImpl {
            name: ECDSA_P384.as_ptr().cast(),
            shortname: SHORT_ECDSA.as_ptr().cast(),
            sigalg: core::ptr::null(),
            type_: KEY_ECDSA,
            nid: 715,
            cert: 0,
            sigonly: 0,
            keybits: 384,
            funcs: core::ptr::null(),
        },
        RustSshkeyImpl {
            name: SSH_RSA.as_ptr().cast(),
            shortname: SHORT_RSA.as_ptr().cast(),
            sigalg: core::ptr::null(),
            type_: KEY_RSA,
            nid: 0,
            cert: 0,
            sigonly: 0,
            keybits: 0,
            funcs: core::ptr::null(),
        },
        RustSshkeyImpl {
            name: SSH_RSA_CERT.as_ptr().cast(),
            shortname: SHORT_RSA_CERT.as_ptr().cast(),
            sigalg: core::ptr::null(),
            type_: KEY_RSA_CERT,
            nid: 0,
            cert: 1,
            sigonly: 0,
            keybits: 0,
            funcs: core::ptr::null(),
        },
        RustSshkeyImpl {
            name: RSA_SHA256.as_ptr().cast(),
            shortname: SHORT_RSA.as_ptr().cast(),
            sigalg: core::ptr::null(),
            type_: KEY_RSA,
            nid: 0,
            cert: 0,
            sigonly: 1,
            keybits: 0,
            funcs: core::ptr::null(),
        },
    ];

    fn entry_ptrs() -> [*const RustSshkeyImpl; ENTRIES.len()] {
        core::array::from_fn(|idx| &ENTRIES[idx] as *const RustSshkeyImpl)
    }

    #[test]
    fn type_lookup_matches_exact_and_short_names() {
        let entry_ptrs = entry_ptrs();
        assert_eq!(
            sshkey_type_from_name(
                b"ssh-ed25519".as_ptr(),
                b"ssh-ed25519".len(),
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
                false,
            ),
            Some(KEY_ED25519)
        );
        assert_eq!(
            sshkey_type_from_name(
                b"rsa-sha2-256".as_ptr(),
                b"rsa-sha2-256".len(),
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
                false,
            ),
            Some(KEY_RSA)
        );
        assert_eq!(
            sshkey_type_from_name(
                b"ecdsa".as_ptr(),
                b"ecdsa".len(),
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
                true,
            ),
            Some(KEY_ECDSA)
        );
    }

    #[test]
    fn name_lookup_preserves_entry_order() {
        let entry_ptrs = entry_ptrs();
        let plain = sshkey_impl_name_from_type_nid(KEY_RSA, 0, false, entry_ptrs.as_ptr(), entry_ptrs.len())
            .unwrap();
        let short = sshkey_impl_name_from_type_nid(KEY_ECDSA, 715, true, entry_ptrs.as_ptr(), entry_ptrs.len())
            .unwrap();
        assert_eq!(unsafe { CStr::from_ptr(plain) }.to_bytes(), b"ssh-rsa");
        assert_eq!(unsafe { CStr::from_ptr(short) }.to_bytes(), b"ECDSA");
    }

    #[test]
    fn ecdsa_nid_lookup_uses_curve_specific_names() {
        let entry_ptrs = entry_ptrs();
        assert_eq!(
            sshkey_ecdsa_nid_from_name(
                b"ecdsa-sha2-nistp384".as_ptr(),
                b"ecdsa-sha2-nistp384".len(),
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            ),
            Some(715)
        );
    }

    #[test]
    fn impl_index_lookup_preserves_first_matching_entry() {
        let entry_ptrs = entry_ptrs();
        assert_eq!(
            sshkey_impl_index_from_type(KEY_RSA, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some(5)
        );
        assert_eq!(
            sshkey_impl_index_from_type_nid(KEY_ECDSA, 715, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some(4)
        );
        assert_eq!(
            sshkey_impl_index_from_type_nid(KEY_RSA, 0, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some(5)
        );
    }

    #[test]
    fn ca_validation_matches_cert_flag() {
        let entry_ptrs = entry_ptrs();
        assert_eq!(
            sshkey_type_is_valid_ca(KEY_ECDSA, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some(true)
        );
        assert_eq!(
            sshkey_type_is_valid_ca(KEY_RSA_CERT, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some(false)
        );
        assert_eq!(
            sshkey_type_is_valid_ca(KEY_ED25519, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some(true)
        );
    }

    #[test]
    fn type_relation_helpers_match_c_semantics() {
        assert!(sshkey_type_is_cert(KEY_RSA_CERT));
        assert!(!sshkey_type_is_cert(KEY_RSA));
        assert_eq!(sshkey_type_plain(KEY_ECDSA_SK_CERT), KEY_ECDSA_SK);
        assert_eq!(sshkey_type_plain(KEY_ED25519_CERT), KEY_ED25519);
        assert_eq!(sshkey_type_certified(KEY_ED25519), Some(KEY_ED25519_CERT));
        assert_eq!(sshkey_type_certified(KEY_ECDSA_SK), Some(KEY_ECDSA_SK_CERT));
        assert_eq!(sshkey_type_certified(KEY_RSA_CERT), None);
        assert!(sshkey_type_is_sk(KEY_ED25519_SK_CERT));
        assert!(!sshkey_type_is_sk(KEY_RSA_CERT));
    }

    #[test]
    fn type_can_new_matches_constructor_rules() {
        let entry_ptrs = entry_ptrs();
        assert_eq!(
            sshkey_type_can_new(KEY_UNSPEC, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some(true)
        );
        assert_eq!(
            sshkey_type_can_new(KEY_ED25519, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some(true)
        );
        assert_eq!(
            sshkey_type_can_new(KEY_ECDSA_CERT, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some(true)
        );
        assert_eq!(
            sshkey_type_can_new(KEY_ECDSA_SK, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some(false)
        );
        assert_eq!(
            sshkey_type_can_new(4242, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some(false)
        );
    }

    #[test]
    fn serialize_plan_matches_cert_and_force_plain_rules() {
        assert_eq!(
            sshkey_serialize_plan(KEY_ED25519_CERT, false, true, 32),
            Ok((KEY_ED25519_CERT, true))
        );
        assert_eq!(
            sshkey_serialize_plan(KEY_ED25519_CERT, true, true, 32),
            Ok((KEY_ED25519, false))
        );
        assert_eq!(
            sshkey_serialize_plan(KEY_ED25519_CERT, false, false, 32),
            Err(SSH_ERR_EXPECTED_CERT)
        );
        assert_eq!(
            sshkey_serialize_plan(KEY_ED25519_CERT, false, true, 0),
            Err(SSH_ERR_KEY_LACKS_CERTBLOB)
        );
    }
}
