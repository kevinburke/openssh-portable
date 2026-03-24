use base64ct::{Base64, Encoding};

use crate::util::{read_slice, write_prefix, SshWireReader};

const MARK_BEGIN: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----\n";
const MARK_END: &[u8] = b"-----END OPENSSH PRIVATE KEY-----\n";
const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";
const KDF_NONE: &[u8] = b"none";
const KDF_BCRYPT: &[u8] = b"bcrypt";

pub(crate) const OSSH_RUST_PRIVATE2_KDF_NONE: u32 = 0;
pub(crate) const OSSH_RUST_PRIVATE2_KDF_BCRYPT: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenSshPrivate2Parse {
    pub(crate) ciphername_offset: usize,
    pub(crate) ciphername_len: usize,
    pub(crate) kdfname_offset: usize,
    pub(crate) kdfname_len: usize,
    pub(crate) kdf_offset: usize,
    pub(crate) kdf_len: usize,
    pub(crate) public_key_offset: usize,
    pub(crate) public_key_len: usize,
    pub(crate) encrypted_offset: usize,
    pub(crate) encrypted_len: usize,
    pub(crate) bcrypt_salt_offset: usize,
    pub(crate) bcrypt_salt_len: usize,
    pub(crate) bcrypt_rounds: u32,
    pub(crate) kdf_kind: u32,
}

pub(crate) fn openssh_private2_decode_len(input: *const u8, input_len: usize) -> usize {
    let Some(input) = read_slice(input, input_len) else {
        return 0;
    };
    decode_private2_armored(input).map_or(0, |decoded| decoded.len())
}

pub(crate) fn openssh_private2_decode_write(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let Some(input) = read_slice(input, input_len) else {
        return -1;
    };
    let decoded = match decode_private2_armored(input) {
        Some(decoded) => decoded,
        None => return -1,
    };
    write_prefix(out, out_len, &decoded)
}

pub(crate) fn openssh_private2_parse(decoded: *const u8, decoded_len: usize) -> Option<OpenSshPrivate2Parse> {
    let decoded = read_slice(decoded, decoded_len)?;
    parse_private2_header(decoded)
}

fn decode_private2_armored(input: &[u8]) -> Option<Vec<u8>> {
    if !input.starts_with(MARK_BEGIN) {
        return None;
    }
    let mut encoded = Vec::new();
    let mut cp = &input[MARK_BEGIN.len()..];

    while !cp.is_empty() {
        if cp[0] != b'\n' && cp[0] != b'\r' {
            encoded.push(cp[0]);
        }
        let last = cp[0];
        cp = &cp[1..];
        if last == b'\n' && cp.starts_with(MARK_END) {
            let decoded = Base64::decode_vec(core::str::from_utf8(&encoded).ok()?).ok()?;
            if !decoded.starts_with(AUTH_MAGIC) {
                return None;
            }
            return Some(decoded);
        }
    }
    None
}

fn parse_private2_header(decoded: &[u8]) -> Option<OpenSshPrivate2Parse> {
    if !decoded.starts_with(AUTH_MAGIC) {
        return None;
    }
    let mut reader = SshWireReader::new(&decoded[AUTH_MAGIC.len()..]);
    let base = AUTH_MAGIC.len();

    let (ciphername_offset, ciphername) = reader.get_string_with_offset()?;
    let (kdfname_offset, kdfname) = reader.get_string_with_offset()?;
    let (kdf_offset, kdf) = reader.get_string_with_offset()?;
    let nkeys = reader.get_u32()?;
    if nkeys != 1 {
        return None;
    }
    let (public_key_offset, public_key) = reader.get_string_with_offset()?;
    let encrypted_len = usize::try_from(reader.get_u32()?).ok()?;
    let encrypted_offset = base + reader.consumed();
    decoded.get(encrypted_offset..encrypted_offset + encrypted_len)?;

    let mut parsed = OpenSshPrivate2Parse {
        ciphername_offset: base + ciphername_offset,
        ciphername_len: ciphername.len(),
        kdfname_offset: base + kdfname_offset,
        kdfname_len: kdfname.len(),
        kdf_offset: base + kdf_offset,
        kdf_len: kdf.len(),
        public_key_offset: base + public_key_offset,
        public_key_len: public_key.len(),
        encrypted_offset,
        encrypted_len,
        bcrypt_salt_offset: 0,
        bcrypt_salt_len: 0,
        bcrypt_rounds: 0,
        kdf_kind: OSSH_RUST_PRIVATE2_KDF_NONE,
    };

    match kdfname {
        KDF_NONE => {
            if !kdf.is_empty() {
                return None;
            }
        }
        KDF_BCRYPT => {
            let mut kdf_reader = SshWireReader::new(kdf);
            let (salt_offset, salt) = kdf_reader.get_string_with_offset()?;
            let rounds = kdf_reader.get_u32()?;
            if kdf_reader.consumed() != kdf.len() {
                return None;
            }
            parsed.bcrypt_salt_offset = base + kdf_offset + salt_offset;
            parsed.bcrypt_salt_len = salt.len();
            parsed.bcrypt_rounds = rounds;
            parsed.kdf_kind = OSSH_RUST_PRIVATE2_KDF_BCRYPT;
        }
        _ => return None,
    }

    Some(parsed)
}

#[cfg(test)]
mod tests {
    use super::{
        openssh_private2_parse, OSSH_RUST_PRIVATE2_KDF_BCRYPT, OSSH_RUST_PRIVATE2_KDF_NONE,
    };

    const ED25519_1: &[u8] =
        include_bytes!("../../../regress/unittests/sshkey/testdata/ed25519_1");
    const ED25519_1_PW: &[u8] =
        include_bytes!("../../../regress/unittests/sshkey/testdata/ed25519_1_pw");

    #[test]
    fn parses_unencrypted_openssh_private_key_header() {
        let decoded_len = super::openssh_private2_decode_len(ED25519_1.as_ptr(), ED25519_1.len());
        assert!(decoded_len > 0);
        let mut decoded = vec![0u8; decoded_len];
        assert_eq!(
            0,
            super::openssh_private2_decode_write(
                ED25519_1.as_ptr(),
                ED25519_1.len(),
                decoded.as_mut_ptr(),
                decoded.len(),
            )
        );
        let parsed = openssh_private2_parse(decoded.as_ptr(), decoded.len()).unwrap();
        assert_eq!(parsed.kdf_kind, OSSH_RUST_PRIVATE2_KDF_NONE);
        assert!(parsed.public_key_len > 0);
        assert!(parsed.encrypted_len > 0);
    }

    #[test]
    fn parses_bcrypt_openssh_private_key_header() {
        let decoded_len = super::openssh_private2_decode_len(ED25519_1_PW.as_ptr(), ED25519_1_PW.len());
        assert!(decoded_len > 0);
        let mut decoded = vec![0u8; decoded_len];
        assert_eq!(
            0,
            super::openssh_private2_decode_write(
                ED25519_1_PW.as_ptr(),
                ED25519_1_PW.len(),
                decoded.as_mut_ptr(),
                decoded.len(),
            )
        );
        let parsed = openssh_private2_parse(decoded.as_ptr(), decoded.len()).unwrap();
        assert_eq!(parsed.kdf_kind, OSSH_RUST_PRIVATE2_KDF_BCRYPT);
        assert!(parsed.bcrypt_salt_len > 0);
        assert!(parsed.bcrypt_rounds > 0);
    }

    #[test]
    fn rejects_missing_markers() {
        assert_eq!(super::openssh_private2_decode_len(b"not a key".as_ptr(), 9), 0);
    }
}
