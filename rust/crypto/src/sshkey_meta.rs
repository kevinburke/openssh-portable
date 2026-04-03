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
const NO_IMPL_INDEX: c_int = -1;
const SSHKEY_CERT_MAX_PRINCIPALS: usize = 256;
const SSH_ERR_KEY_CERT_INVALID_SIGN_KEY: c_int = -19;
const SSH_ERR_INVALID_ARGUMENT: c_int = -10;
const SSH_ERR_EXPECTED_CERT: c_int = -16;
const SSH_ERR_KEY_LACKS_CERTBLOB: c_int = -17;
pub(crate) const SSHKEY_SIGALG_MATCH_DIRECT: c_int = 0;
pub(crate) const SSHKEY_SIGALG_MATCH_RSA: c_int = 1;
pub(crate) const SSHKEY_SIGALG_MATCH_RSA_CERT: c_int = 2;
pub(crate) const SSHKEY_SIGALG_MATCH_ECDSA_SK: c_int = 3;
pub(crate) const SSHKEY_SIGALG_MATCH_ECDSA_SK_CERT: c_int = 4;

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

fn parse_ecdsa_type_name(input: &[u8]) -> Option<c_int> {
    match input {
        b"ecdsa-sha2-nistp256"
        | b"ecdsa-sha2-nistp384"
        | b"ecdsa-sha2-nistp521" => Some(KEY_ECDSA),
        b"ecdsa-sha2-nistp256-cert-v01@openssh.com"
        | b"ecdsa-sha2-nistp384-cert-v01@openssh.com"
        | b"ecdsa-sha2-nistp521-cert-v01@openssh.com" => Some(KEY_ECDSA_CERT),
        b"sk-ecdsa-sha2-nistp256@openssh.com"
        | b"webauthn-sk-ecdsa-sha2-nistp256@openssh.com" => Some(KEY_ECDSA_SK),
        b"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
        | b"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" => Some(KEY_ECDSA_SK_CERT),
        _ => None,
    }
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

pub(crate) fn sshkey_generate_plan(
    type_: c_int,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Result<c_int, c_int> {
    if sshkey_type_is_cert(type_) {
        return Err(-1);
    }
    sshkey_impl_index_from_type(type_, entries, nentries).ok_or(-2)?;
    Ok(type_)
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

pub(crate) fn sshkey_from_private_plan(
    type_: c_int,
    nid: c_int,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Option<(c_int, bool)> {
    sshkey_impl_index_from_type_nid(type_, nid, entries, nentries)?;
    Some((type_, sshkey_type_is_cert(type_)))
}

pub(crate) fn sshkey_cert_copy_plan(
    has_cert: bool,
    has_signature_key: bool,
    nprincipals: usize,
) -> Result<bool, c_int> {
    if !has_cert {
        return Err(SSH_ERR_INVALID_ARGUMENT);
    }
    if nprincipals > SSHKEY_CERT_MAX_PRINCIPALS as usize {
        return Err(SSH_ERR_INVALID_ARGUMENT);
    }
    Ok(has_signature_key)
}

pub(crate) fn sshkey_copy_public_sk_plan(has_application: bool) -> Result<(), c_int> {
    if !has_application {
        return Err(SSH_ERR_INVALID_ARGUMENT);
    }
    Ok(())
}

pub(crate) fn sshkey_sigalg_match_plan(
    input: *const u8,
    input_len: usize,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Option<c_int> {
    let type_ = sshkey_type_from_name(input, input_len, entries, nentries, false)?;
    Some(match type_ {
        KEY_RSA => SSHKEY_SIGALG_MATCH_RSA,
        KEY_RSA_CERT => SSHKEY_SIGALG_MATCH_RSA_CERT,
        KEY_ECDSA_SK => SSHKEY_SIGALG_MATCH_ECDSA_SK,
        KEY_ECDSA_SK_CERT => SSHKEY_SIGALG_MATCH_ECDSA_SK_CERT,
        _ => SSHKEY_SIGALG_MATCH_DIRECT,
    })
}

pub(crate) fn sshkey_sigalg_by_name(
    input: *const u8,
    input_len: usize,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Option<*const c_char> {
    let input = read_input(input, input_len)?;
    let entries_slice = keyimpls(entries, nentries)?;

    for entry_ptr in entries_slice {
        let entry = entry_ref(*entry_ptr)?;
        let name = entry_bytes(entry.name)?;
        if name != input {
            continue;
        }
        if !entry.sigalg.is_null() {
            return Some(entry.sigalg);
        }
        if entry.cert == 0 {
            return Some(entry.name);
        }
        let plain = sshkey_type_plain(entry.type_);
        return sshkey_impl_name_from_type_nid(plain, entry.nid, false, entries, nentries);
    }
    None
}

pub(crate) fn sshkey_alg_list_include(
    certs_only: bool,
    plain_only: bool,
    include_sigonly: bool,
    entry: *const RustSshkeyImpl,
) -> Option<bool> {
    let entry = entry_ref(entry)?;
    if entry.name.is_null() {
        return Some(false);
    }
    if !include_sigonly && entry.sigonly != 0 {
        return Some(false);
    }
    if (certs_only && entry.cert == 0) || (plain_only && entry.cert != 0) {
        return Some(false);
    }
    Some(true)
}

pub(crate) fn sshkey_names_valid_include(
    input: *const u8,
    input_len: usize,
    allow_wildcard: bool,
    plain_only: bool,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Option<bool> {
    let input = read_input(input, input_len)?;
    if input.is_empty() {
        return Some(false);
    }
    if let Some(type_) = sshkey_type_from_name(input.as_ptr(), input.len(), entries, nentries, false)
    {
        return Some(!(plain_only && sshkey_type_is_cert(type_)));
    }
    if !allow_wildcard {
        return Some(false);
    }
    let entries_slice = keyimpls(entries, nentries)?;
    for entry_ptr in entries_slice {
        let entry = entry_ref(*entry_ptr)?;
        let name = entry_bytes(entry.name)?;
        if wildcard_match(input, name) {
            return Some(true);
        }
    }
    Some(false)
}

fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    wildcard_match_from(pattern, text)
}

fn wildcard_match_from(pattern: &[u8], text: &[u8]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    match pattern[0] {
        b'*' => {
            wildcard_match_from(&pattern[1..], text)
                || (!text.is_empty() && wildcard_match_from(pattern, &text[1..]))
        }
        b'?' => !text.is_empty() && wildcard_match_from(&pattern[1..], &text[1..]),
        ch => !text.is_empty() && ch == text[0] && wildcard_match_from(&pattern[1..], &text[1..]),
    }
}

pub(crate) fn sshkey_equal_public_plan(
    lhs_type: c_int,
    rhs_type: c_int,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Option<(bool, c_int)> {
    if sshkey_type_plain(lhs_type) != sshkey_type_plain(rhs_type) {
        return Some((false, lhs_type));
    }
    sshkey_impl_index_from_type(lhs_type, entries, nentries)?;
    Some((true, lhs_type))
}

pub(crate) fn sshkey_equal_plan(
    lhs_type: c_int,
    rhs_type: c_int,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Option<(bool, c_int)> {
    if lhs_type != rhs_type {
        return Some((false, KEY_UNSPEC));
    }
    sshkey_impl_index_from_type(lhs_type, entries, nentries)?;
    Some((sshkey_type_is_cert(lhs_type), lhs_type))
}

pub(crate) fn sshkey_from_blob_plan(
    input: *const u8,
    input_len: usize,
    allow_cert: bool,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Result<(c_int, c_int, bool), c_int> {
    let type_ = sshkey_type_from_name(input, input_len, entries, nentries, false)
        .ok_or(-14)?;
    if !allow_cert && sshkey_type_is_cert(type_) {
        return Err(SSH_ERR_KEY_CERT_INVALID_SIGN_KEY);
    }
    if let Some(index) = sshkey_impl_index_from_type(type_, entries, nentries) {
        return Ok((type_, index as c_int, false));
    }
    if is_ecdsa_variant(type_) && sshkey_type_plain(type_) == KEY_ECDSA {
        return Ok((type_, NO_IMPL_INDEX, true));
    }
    Err(-14)
}

pub(crate) fn sshkey_private_deserialize_plan(
    input: *const u8,
    input_len: usize,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Option<(c_int, bool, c_int, c_int)> {
    let type_ = sshkey_type_from_name(input, input_len, entries, nentries, false)?;
    let is_cert = sshkey_type_is_cert(type_);
    let impl_index = sshkey_impl_index_from_type(type_, entries, nentries)
        .map(|idx| idx as c_int)
        .unwrap_or(NO_IMPL_INDEX);
    let expected_cert_nid = if type_ == KEY_ECDSA_CERT {
        sshkey_ecdsa_nid_from_name(input, input_len, entries, nentries)?
    } else {
        -1
    };
    Some((type_, is_cert, impl_index, expected_cert_nid))
}

pub(crate) fn sshkey_private_serialize_plan(
    type_: c_int,
    nid: c_int,
    has_cert: bool,
    certblob_len: usize,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Result<c_int, c_int> {
    if sshkey_type_is_cert(type_) && (!has_cert || certblob_len == 0) {
        return Err(SSH_ERR_INVALID_ARGUMENT);
    }
    sshkey_impl_index_from_type_nid(type_, nid, entries, nentries)
        .map(|idx| idx as c_int)
        .ok_or(-1)
}

pub(crate) fn sshkey_free_contents_plan(
    type_: c_int,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
) -> Option<(bool, c_int)> {
    if let Some(index) = sshkey_impl_index_from_type(type_, entries, nentries) {
        return Some((sshkey_type_is_cert(type_), index as c_int));
    }
    Some((sshkey_type_is_cert(type_), NO_IMPL_INDEX))
}

pub(crate) fn sshkey_type_from_name(
    input: *const u8,
    input_len: usize,
    entries: *const *const RustSshkeyImpl,
    nentries: usize,
    allow_short: bool,
) -> Option<c_int> {
    let input = read_input(input, input_len)?;
    if let Some(type_) = parse_ecdsa_type_name(input) {
        return Some(type_);
    }
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

    #[test]
    fn generate_plan_rejects_cert_and_unknown_types() {
        let entry_ptrs = entry_ptrs();
        assert_eq!(
            sshkey_generate_plan(KEY_ED25519, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Ok(KEY_ED25519)
        );
        assert_eq!(
            sshkey_generate_plan(KEY_ED25519_CERT, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Err(-1)
        );
        assert_eq!(
            sshkey_generate_plan(4242, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Err(-2)
        );
    }

    #[test]
    fn from_private_plan_requires_supported_type_and_tracks_cert_copy() {
        let entry_ptrs = entry_ptrs();
        assert_eq!(
            sshkey_from_private_plan(KEY_ED25519, 0, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some((KEY_ED25519, false))
        );
        assert_eq!(
            sshkey_from_private_plan(KEY_ECDSA_CERT, 415, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some((KEY_ECDSA_CERT, true))
        );
        assert_eq!(
            sshkey_from_private_plan(KEY_ECDSA_CERT, 999, entry_ptrs.as_ptr(), entry_ptrs.len()),
            None
        );
    }

    #[test]
    fn equal_public_plan_checks_plain_type_compatibility() {
        let entry_ptrs = entry_ptrs();
        assert_eq!(
            sshkey_equal_public_plan(KEY_ED25519_CERT, KEY_ED25519, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some((true, KEY_ED25519_CERT))
        );
        assert_eq!(
            sshkey_equal_public_plan(KEY_ED25519, KEY_RSA, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some((false, KEY_ED25519))
        );
        assert_eq!(
            sshkey_equal_public_plan(KEY_ECDSA_SK, KEY_ECDSA_SK, entry_ptrs.as_ptr(), entry_ptrs.len()),
            None
        );
    }

    #[test]
    fn equal_plan_requires_exact_type_and_tracks_cert_compare() {
        let entry_ptrs = entry_ptrs();
        assert_eq!(
            sshkey_equal_plan(KEY_ED25519_CERT, KEY_ED25519_CERT, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some((true, KEY_ED25519_CERT))
        );
        assert_eq!(
            sshkey_equal_plan(KEY_ED25519_CERT, KEY_ED25519, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some((false, KEY_UNSPEC))
        );
        assert_eq!(
            sshkey_equal_plan(KEY_ECDSA_SK, KEY_ECDSA_SK, entry_ptrs.as_ptr(), entry_ptrs.len()),
            None
        );
    }

    #[test]
    fn from_blob_plan_handles_cert_policy_and_noec_fallback() {
        let entry_ptrs = entry_ptrs();
        let noec_entry_ptrs: Vec<*const RustSshkeyImpl> = entry_ptrs
            .iter()
            .copied()
            .filter(|entry_ptr| {
                let entry = entry_ref(*entry_ptr).unwrap();
                !is_ecdsa_variant(entry.type_)
            })
            .collect();
        assert_eq!(
            sshkey_from_blob_plan(
                b"ssh-ed25519".as_ptr(),
                b"ssh-ed25519".len(),
                true,
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            ),
            Ok((
                KEY_ED25519,
                sshkey_impl_index_from_type(KEY_ED25519, entry_ptrs.as_ptr(), entry_ptrs.len())
                    .unwrap() as c_int,
                false,
            ))
        );
        assert_eq!(
            sshkey_from_blob_plan(
                b"ecdsa-sha2-nistp256-cert-v01@openssh.com".as_ptr(),
                b"ecdsa-sha2-nistp256-cert-v01@openssh.com".len(),
                false,
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            ),
            Err(SSH_ERR_KEY_CERT_INVALID_SIGN_KEY)
        );
        assert_eq!(
            sshkey_from_blob_plan(
                b"ecdsa-sha2-nistp256-cert-v01@openssh.com".as_ptr(),
                b"ecdsa-sha2-nistp256-cert-v01@openssh.com".len(),
                true,
                noec_entry_ptrs.as_ptr(),
                noec_entry_ptrs.len(),
            ),
            Ok((KEY_ECDSA_CERT, NO_IMPL_INDEX, true))
        );
    }

    #[test]
    fn cert_copy_plan_tracks_signature_key_and_principal_limits() {
        assert_eq!(sshkey_cert_copy_plan(true, false, 0), Ok(false));
        assert_eq!(sshkey_cert_copy_plan(true, true, 1), Ok(true));
        assert_eq!(
            sshkey_cert_copy_plan(false, false, 0),
            Err(SSH_ERR_INVALID_ARGUMENT)
        );
        assert_eq!(
            sshkey_cert_copy_plan(
                true,
                false,
                (SSHKEY_CERT_MAX_PRINCIPALS as usize).saturating_add(1),
            ),
            Err(SSH_ERR_INVALID_ARGUMENT)
        );
    }

    #[test]
    fn copy_public_sk_plan_requires_application() {
        assert_eq!(sshkey_copy_public_sk_plan(true), Ok(()));
        assert_eq!(
            sshkey_copy_public_sk_plan(false),
            Err(SSH_ERR_INVALID_ARGUMENT)
        );
    }

    #[test]
    fn sigalg_match_plan_classifies_special_cases() {
        let entry_ptrs = entry_ptrs();
        assert_eq!(
            sshkey_sigalg_match_plan(
                b"ssh-ed25519".as_ptr(),
                b"ssh-ed25519".len(),
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            ),
            Some(SSHKEY_SIGALG_MATCH_DIRECT)
        );
        assert_eq!(
            sshkey_sigalg_match_plan(
                b"ssh-rsa".as_ptr(),
                b"ssh-rsa".len(),
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            ),
            Some(SSHKEY_SIGALG_MATCH_RSA)
        );
        assert_eq!(
            sshkey_sigalg_match_plan(
                b"ssh-rsa-cert-v01@openssh.com".as_ptr(),
                b"ssh-rsa-cert-v01@openssh.com".len(),
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            ),
            Some(SSHKEY_SIGALG_MATCH_RSA_CERT)
        );
        assert_eq!(
            sshkey_sigalg_match_plan(
                b"sk-ecdsa-sha2-nistp256@openssh.com".as_ptr(),
                b"sk-ecdsa-sha2-nistp256@openssh.com".len(),
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            ),
            Some(SSHKEY_SIGALG_MATCH_ECDSA_SK)
        );
    }

    #[test]
    fn sigalg_by_name_returns_expected_name() {
        let entry_ptrs = entry_ptrs();
        assert_eq!(
            unsafe {
                CStr::from_ptr(
                    sshkey_sigalg_by_name(
                        b"rsa-sha2-256".as_ptr(),
                        b"rsa-sha2-256".len(),
                        entry_ptrs.as_ptr(),
                        entry_ptrs.len(),
                    )
                    .unwrap(),
                )
            }
            .to_bytes(),
            b"rsa-sha2-256"
        );
        assert_eq!(
            unsafe {
                CStr::from_ptr(
                    sshkey_sigalg_by_name(
                        b"ssh-rsa-cert-v01@openssh.com".as_ptr(),
                        b"ssh-rsa-cert-v01@openssh.com".len(),
                        entry_ptrs.as_ptr(),
                        entry_ptrs.len(),
                    )
                    .unwrap(),
                )
            }
            .to_bytes(),
            b"ssh-rsa"
        );
    }

    #[test]
    fn alg_list_include_matches_current_filters() {
        let entry_ptrs = entry_ptrs();

        assert_eq!(
            sshkey_alg_list_include(false, false, false, entry_ptrs[0]),
            Some(true)
        );
        assert_eq!(
            sshkey_alg_list_include(true, false, false, entry_ptrs[0]),
            Some(false)
        );
        assert_eq!(
            sshkey_alg_list_include(false, true, false, entry_ptrs[0]),
            Some(true)
        );
        assert_eq!(
            sshkey_alg_list_include(false, false, false, entry_ptrs[7]),
            Some(false)
        );
        assert_eq!(
            sshkey_alg_list_include(false, false, true, entry_ptrs[7]),
            Some(true)
        );
    }

    #[test]
    fn names_valid_include_matches_exact_and_wildcard_cases() {
        let entry_ptrs = entry_ptrs();

        assert_eq!(
            sshkey_names_valid_include(
                b"ssh-ed25519".as_ptr(),
                b"ssh-ed25519".len(),
                false,
                false,
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            ),
            Some(true)
        );
        assert_eq!(
            sshkey_names_valid_include(
                b"ssh-rsa-cert-v01@openssh.com".as_ptr(),
                b"ssh-rsa-cert-v01@openssh.com".len(),
                false,
                true,
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            ),
            Some(false)
        );
        assert_eq!(
            sshkey_names_valid_include(
                b"ssh-*".as_ptr(),
                b"ssh-*".len(),
                true,
                false,
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            ),
            Some(true)
        );
        assert_eq!(
            sshkey_names_valid_include(
                b"bogus-*".as_ptr(),
                b"bogus-*".len(),
                true,
                false,
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            ),
            Some(false)
        );
    }

    #[test]
    fn private_deserialize_plan_tracks_cert_and_impl_selection() {
        let entry_ptrs = entry_ptrs();
        assert_eq!(
            sshkey_private_deserialize_plan(
                b"ssh-ed25519".as_ptr(),
                b"ssh-ed25519".len(),
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            ),
            Some((
                KEY_ED25519,
                false,
                sshkey_impl_index_from_type(KEY_ED25519, entry_ptrs.as_ptr(), entry_ptrs.len())
                    .unwrap() as c_int,
                -1,
            ))
        );
        assert_eq!(
            sshkey_private_deserialize_plan(
                b"ecdsa-sha2-nistp256-cert-v01@openssh.com".as_ptr(),
                b"ecdsa-sha2-nistp256-cert-v01@openssh.com".len(),
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            ),
            Some((
                KEY_ECDSA_CERT,
                true,
                sshkey_impl_index_from_type(KEY_ECDSA_CERT, entry_ptrs.as_ptr(), entry_ptrs.len())
                    .unwrap() as c_int,
                415,
            ))
        );
    }

    #[test]
    fn private_serialize_plan_requires_certblob_and_impl() {
        let entry_ptrs = entry_ptrs();
        assert_eq!(
            sshkey_private_serialize_plan(
                KEY_ED25519,
                0,
                false,
                0,
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            ),
            Ok(sshkey_impl_index_from_type_nid(
                KEY_ED25519,
                0,
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            )
            .unwrap() as c_int)
        );
        assert_eq!(
            sshkey_private_serialize_plan(
                KEY_ED25519_CERT,
                0,
                false,
                0,
                entry_ptrs.as_ptr(),
                entry_ptrs.len(),
            ),
            Err(SSH_ERR_INVALID_ARGUMENT)
        );
    }

    #[test]
    fn free_contents_plan_tracks_cert_and_optional_cleanup_dispatch() {
        let entry_ptrs = entry_ptrs();
        assert_eq!(
            sshkey_free_contents_plan(KEY_ED25519_CERT, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some((
                true,
                sshkey_impl_index_from_type(KEY_ED25519_CERT, entry_ptrs.as_ptr(), entry_ptrs.len())
                    .unwrap() as c_int,
            ))
        );
        assert_eq!(
            sshkey_free_contents_plan(KEY_UNSPEC, entry_ptrs.as_ptr(), entry_ptrs.len()),
            Some((false, NO_IMPL_INDEX))
        );
    }
}
